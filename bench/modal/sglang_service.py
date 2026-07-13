"""SGLang inference server on Modal (thin engine file over ``_serving``).

Serves one model behind an OpenAI-compatible endpoint (``/v1/chat/completions``
with XGrammar structured output) — the stand-in for the future in-cluster
self-hosted tier (#13). Deploy in module mode, once per model:

    SGLANG_MODEL="Qwen/Qwen3-14B" SGLANG_API_KEY="$KEY" \
        modal deploy -m bench.modal.sglang_service

Pre-stage weights first (cheap CPU box) so the GPU isn't billing during the
download:

    SGLANG_MODEL="..." modal run -m bench.modal.sglang_service::download
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

import modal

from ._serving import (
    HF_CACHE_DIR,
    MAX_CONCURRENT,
    MINUTES,
    SCALEDOWN_S,
    EngineSpec,
    do_download,
    download_image,
    hf_cache,
    hf_secret,
    masked,
    require_auth,
    resolve,
    runtime_cfg,
    runtime_model_id,
    runtime_secret,
    serve_image,
)

SPEC = EngineSpec(
    name="sglang",
    registry_ref="lmsysorg/sglang:{tag}",
    port=30000,
    health_path="/health_generate",
    model_env="SGLANG_MODEL",
    api_key_env="SGLANG_API_KEY",
    gpu_env="SGLANG_GPU",
    tag_env="SGLANG_IMAGE_TAG",
)

MODEL_CONFIGS: dict[str, dict[str, Any]] = {
    # GPUs right-sized to the smallest that fits (cost) — L4 ~$0.80/hr,
    # L40S ~$1.95/hr, A100-80GB ~$3/hr. The triage eval uses short prompts, so a
    # 16k context is plenty for the small tiers.
    "Qwen/Qwen3-14B": dict(
        gpu="L40S", tp=1, context_length=32768,
        tool_call_parser="qwen", reasoning_parser="qwen3",
        image_tag="v0.5.8", startup_min=20,
    ),
    "Qwen/Qwen3-32B": dict(
        gpu="A100-80GB", tp=1, context_length=32768,
        tool_call_parser="qwen", reasoning_parser="qwen3",
        image_tag="v0.5.8", startup_min=20,
    ),
    # --- DeepSeek R1-Distill (Qwen base) parameter ladder: low → high ---
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B": dict(
        gpu="L4", tp=1, context_length=16384,
        tool_call_parser="deepseekv3", reasoning_parser="deepseek-r1",
        image_tag="v0.5.8", startup_min=12,
    ),
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B": dict(
        gpu="L4", tp=1, context_length=16384,
        tool_call_parser="deepseekv3", reasoning_parser="deepseek-r1",
        image_tag="v0.5.8", startup_min=15,
    ),
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B": dict(
        gpu="L40S", tp=1, context_length=32768,
        tool_call_parser="deepseekv3", reasoning_parser="deepseek-r1",
        image_tag="v0.5.8", startup_min=18,
    ),
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B": dict(
        gpu="A100-80GB", tp=1, context_length=32768,
        tool_call_parser="deepseekv3", reasoning_parser="deepseek-r1",
        image_tag="v0.5.8", startup_min=20,
    ),
    # --- flagship MoE (multi-GPU, FP8) ---
    "Qwen/Qwen3-235B-A22B-Thinking-2507-FP8": dict(
        gpu="H100:4", tp=4, context_length=32768,
        tool_call_parser="qwen", reasoning_parser="deepseek-r1",
        image_tag="nightly-dev-cu12-20260710-cfc66e05", startup_min=45,
    ),
}

def build_command(model_id: str, cfg: dict[str, Any], api_key: str) -> list[str]:
    cmd = [
        "python", "-m", "sglang.launch_server",
        "--model-path", model_id,
        "--host", "0.0.0.0", "--port", str(SPEC.port),
        "--tp", str(cfg["tp"]),
        "--context-length", str(cfg["context_length"]),
        "--grammar-backend", "xgrammar",
        "--mem-fraction-static", "0.85",
    ]
    if cfg.get("tool_call_parser"):
        cmd += ["--tool-call-parser", str(cfg["tool_call_parser"])]
    if cfg.get("reasoning_parser"):
        cmd += ["--reasoning-parser", str(cfg["reasoning_parser"])]
    if api_key:
        cmd += ["--api-key", api_key]
    return cmd


require_auth(SPEC)
_R = resolve(SPEC, MODEL_CONFIGS)
app = modal.App(_R.app_name)
_secret = runtime_secret(_R.model_id, SPEC.api_key_env)


@app.function(
    image=download_image,
    volumes={HF_CACHE_DIR: hf_cache},
    secrets=[hf_secret(), _secret],
    timeout=60 * MINUTES,
)
def download() -> None:
    do_download(runtime_model_id())


@app.function(
    image=serve_image(SPEC.registry_ref.format(tag=_R.tag)),
    gpu=_R.gpu,
    volumes={HF_CACHE_DIR: hf_cache},
    secrets=[hf_secret(), _secret],
    timeout=60 * MINUTES,
    scaledown_window=SCALEDOWN_S,
)
@modal.concurrent(max_inputs=MAX_CONCURRENT)
@modal.web_server(port=SPEC.port, startup_timeout=_R.startup_s)
def serve() -> None:
    model_id = runtime_model_id()
    cfg = runtime_cfg(MODEL_CONFIGS, model_id)
    api_key = os.environ.get(SPEC.api_key_env, "")
    cmd = build_command(model_id, cfg, api_key)
    print("launching:", masked(cmd), flush=True)
    subprocess.Popen(cmd)
