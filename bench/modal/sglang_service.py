"""SGLang inference server on Modal — an OpenAI-compatible endpoint for
benchmarking open models against soctalk's triage eval (issues #13 / #32 / #9).

This is a stand-in for the future in-cluster SGLang tier (#13): it serves an
open model behind the same OpenAI-compatible surface (`/v1/chat/completions`
with `response_format` JSON-schema / XGrammar structured output) that
soctalk's `openai` provider path already talks to. Pointing the eval at this
endpoint exercises the exact self-hosted-tier path #32 defines, before any
Helm is written.

The served model is chosen by env at deploy time; per-model serving config
(GPU count, tensor-parallel, parsers, SGLang image) lives in MODEL_CONFIGS so
one file serves the whole lineup. Deploy once per model:

    SGLANG_MODEL="Qwen/Qwen3-14B" SGLANG_API_KEY="$KEY" modal deploy bench/modal/sglang_service.py

For big models, pre-stage the weights into the shared Volume with a cheap
CPU job first so the expensive GPUs aren't billing during the download:

    SGLANG_MODEL="..." modal run bench/modal/sglang_service.py::download

Auth: the endpoint requires `Authorization: Bearer $SGLANG_API_KEY` (SGLang's
`--api-key`), which the OpenAI client sends as its API key. The Modal workspace
token is read from your local `~/.modal.toml`; nothing secret is in this file.
"""

from __future__ import annotations

import os
import subprocess

import modal

# --- Per-model serving config -------------------------------------------------
# gpu: Modal GPU spec ("A100-80GB", or "H100:4" for a 4-GPU tensor-parallel box).
# tool_call_parser / reasoning_parser: the SGLang flags that let a model emit
# tool calls (what LangChain's with_structured_output uses) and separate its
# chain-of-thought. image_tag pins the SGLang build — the flagship MoE models
# postdate the stable v0.5.8, so they need a current nightly.
MODEL_CONFIGS: dict[str, dict[str, object]] = {
    "Qwen/Qwen3-14B": dict(
        gpu="A100-80GB", tp=1, context_length=32768,
        tool_call_parser="qwen", reasoning_parser="qwen3",
        image_tag="v0.5.8", startup_min=20,
    ),
    "Qwen/Qwen3-32B": dict(
        gpu="A100-80GB", tp=1, context_length=32768,
        tool_call_parser="qwen", reasoning_parser="qwen3",
        image_tag="v0.5.8", startup_min=20,
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
    # DeepSeek-V4-Flash: FP4(MoE)+FP8, novel CSA/HCA attention. GPU/parser/image
    # are provisional pending the serving-recipe research; may move to B200.
    "deepseek-ai/DeepSeek-V4-Flash": dict(
        gpu="H100:4", tp=4, context_length=32768,
        tool_call_parser="deepseekv3", reasoning_parser="deepseek-v3",
        image_tag="nightly-dev-cu12-20260710-cfc66e05", startup_min=50,
    ),
}

MODEL_ID = os.environ.get("SGLANG_MODEL", "Qwen/Qwen3-14B")
API_KEY = os.environ.get("SGLANG_API_KEY", "")

_cfg = MODEL_CONFIGS.get(
    MODEL_ID,
    dict(gpu="A100-80GB", tp=1, context_length=32768,
         tool_call_parser=None, reasoning_parser=None,
         image_tag="v0.5.8", startup_min=20),
)
GPU = os.environ.get("SGLANG_GPU", str(_cfg["gpu"]))
SGLANG_TAG = os.environ.get("SGLANG_IMAGE_TAG", str(_cfg["image_tag"]))
STARTUP_S = int(_cfg["startup_min"]) * 60

_slug = MODEL_ID.split("/")[-1].lower().replace(".", "-").replace("_", "-")
app = modal.App(f"soctalk-sglang-{_slug}")

# The official SGLang image ships a matching CUDA + torch + flashinfer + xgrammar
# stack. Clear the base entrypoint so Modal controls the process, and make sure
# `python` resolves.
sglang_image = (
    modal.Image.from_registry(f"lmsysorg/sglang:{SGLANG_TAG}")
    .entrypoint([])
    .run_commands("ln -sf $(which python3) /usr/local/bin/python || true")
)

# A lighter CPU image just for pre-staging weights into the Volume.
download_image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("huggingface_hub[hf_transfer]>=0.34")
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1"})
)

# Cache HF weights across cold starts so a model downloads only once.
hf_cache = modal.Volume.from_name("soctalk-hf-cache", create_if_missing=True)

# HF token is optional (the lineup is ungated); pass one through if the local
# env has it, else an empty secret so `secrets=[...]` is always valid.
_hf_token = os.environ.get("HF_TOKEN", "")
hf_secret = modal.Secret.from_dict({"HF_TOKEN": _hf_token} if _hf_token else {})

MINUTES = 60
HF_CACHE_DIR = "/root/.cache/huggingface"


@app.function(
    image=download_image,
    volumes={HF_CACHE_DIR: hf_cache},
    secrets=[hf_secret],
    timeout=60 * MINUTES,
)
def download() -> None:
    """Pre-stage MODEL_ID weights into the shared Volume on a cheap CPU box so
    the GPU server finds them cached and loads fast (no GPU billing during the
    download)."""
    from huggingface_hub import snapshot_download

    print(f"downloading {MODEL_ID} into the volume ...", flush=True)
    snapshot_download(MODEL_ID, cache_dir=HF_CACHE_DIR)
    hf_cache.commit()
    print("done", flush=True)


@app.function(
    image=sglang_image,
    gpu=GPU,
    volumes={HF_CACHE_DIR: hf_cache},
    secrets=[hf_secret],
    timeout=60 * MINUTES,
    # Keep the GPU warm briefly after the last request, then scale to zero so
    # an idle benchmark run stops billing.
    scaledown_window=5 * MINUTES,
)
@modal.concurrent(max_inputs=64)
@modal.web_server(port=30000, startup_timeout=STARTUP_S)
def serve() -> None:
    cmd: list[str] = [
        "python", "-m", "sglang.launch_server",
        "--model-path", MODEL_ID,
        "--host", "0.0.0.0",
        "--port", "30000",
        "--tp", str(_cfg["tp"]),
        "--context-length", str(_cfg["context_length"]),
        "--grammar-backend", "xgrammar",
        "--mem-fraction-static", "0.85",
    ]
    if _cfg.get("tool_call_parser"):
        cmd += ["--tool-call-parser", str(_cfg["tool_call_parser"])]
    if _cfg.get("reasoning_parser"):
        cmd += ["--reasoning-parser", str(_cfg["reasoning_parser"])]
    if API_KEY:
        cmd += ["--api-key", API_KEY]
    print("launching:", " ".join(cmd), flush=True)
    subprocess.Popen(cmd)
