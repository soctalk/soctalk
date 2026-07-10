"""vLLM inference server on Modal (thin engine file over ``_serving``).

The vLLM sibling of ``sglang_service.py``: serves one model behind the same
OpenAI-compatible surface (``/v1/chat/completions`` with
``extra_body.structured_outputs`` guided decoding). Deploy in module mode:

    VLLM_MODEL="Qwen/Qwen3-14B" VLLM_API_KEY="$KEY" \
        modal deploy -m bench.modal.vllm_service
    VLLM_MODEL="..." modal run -m bench.modal.vllm_service::download
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
    name="vllm",
    registry_ref="vllm/vllm-openai:{tag}",
    port=8000,
    health_path="/health",
    model_env="VLLM_MODEL",
    api_key_env="VLLM_API_KEY",
    gpu_env="VLLM_GPU",
    tag_env="VLLM_IMAGE_TAG",
)

# Structured outputs are ON by default (xgrammar). Qwen3 thinking is disabled
# server-side so xgrammar doesn't skip enforcement in the reasoning span (and
# so constrained output isn't preceded by CoT tokens).
MODEL_CONFIGS: dict[str, dict[str, Any]] = {
    "Qwen/Qwen3-14B": dict(
        gpu="A100-80GB", tp=1, max_model_len=32768,
        disable_thinking=True, image_tag="v0.24.0", startup_min=20,
    ),
    "Qwen/Qwen3-32B": dict(
        gpu="A100-80GB", tp=1, max_model_len=32768,
        disable_thinking=True, image_tag="v0.24.0", startup_min=20,
    ),
}

def build_command(model_id: str, cfg: dict[str, Any], api_key: str) -> list[str]:
    cmd = [
        "vllm", "serve", model_id,
        "--host", "0.0.0.0", "--port", str(SPEC.port),
        "--tensor-parallel-size", str(cfg["tp"]),
        "--max-model-len", str(cfg["max_model_len"]),
        "--gpu-memory-utilization", "0.90",
    ]
    if cfg.get("disable_thinking"):
        cmd += ["--default-chat-template-kwargs", '{"enable_thinking": false}']
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
