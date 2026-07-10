"""Shared Modal serving scaffolding for the bench engine services.

SGLang and vLLM are served the same way — an OpenAI-compatible server behind a
Modal web endpoint, weights cached in a shared Volume, scale-to-zero — differing
only in image, launch command, port, and health path. This module holds the
engine-agnostic parts; each engine file stays thin (an EngineSpec + its
MODEL_CONFIGS + a build_command) and keeps its own explicit Modal decorators.

Deploy in MODULE mode so the relative import of this helper is included in the
remote container image (script-path mode would omit it):

    modal deploy -m bench.modal.sglang_service
    modal run    -m bench.modal.sglang_service::download

Critical: the served model/key must reach the CONTAINER, not just the deploy
process. Modal re-imports the module remotely (serialized=False), so a value
read from os.environ at import time is NOT present in the container — it would
silently default. We therefore bake the resolved model id and API key into a
Modal Secret (injected as container env), read back inside serve()/download().
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import modal

HF_CACHE_DIR = "/root/.cache/huggingface"
MINUTES = 60
MAX_CONCURRENT = 64
SCALEDOWN_S = 5 * 60

# The env var name the container reads to learn which model to serve. Injected
# via a Modal Secret from the deploy-side resolution.
RUNTIME_MODEL_ENV = "SOCTALK_BENCH_MODEL"

# Shared weight cache across cold starts and across engines.
hf_cache = modal.Volume.from_name("soctalk-hf-cache", create_if_missing=True)


def hf_secret() -> modal.Secret:
    """Optional HF token (the lineup is ungated); empty secret if unset."""
    tok = os.environ.get("HF_TOKEN", "")
    return modal.Secret.from_dict({"HF_TOKEN": tok} if tok else {})


def runtime_secret(model_id: str, api_key_env: str) -> modal.Secret:
    """Bake the deploy-side model id + API key into a Secret so the CONTAINER
    gets them via env (module globals wouldn't survive the remote re-import)."""
    return modal.Secret.from_dict({
        RUNTIME_MODEL_ENV: model_id,
        api_key_env: os.environ.get(api_key_env, ""),
    })


def require_auth(spec: EngineSpec) -> None:
    """Fail closed at deploy time (locally, before any spend) if no bearer key
    is set — refuse to stand up an unauthenticated GPU endpoint. Set
    ``BENCH_ALLOW_NO_AUTH=1`` to opt into an open endpoint deliberately."""
    if not os.environ.get(spec.api_key_env) and not os.environ.get("BENCH_ALLOW_NO_AUTH"):
        raise SystemExit(
            f"{spec.api_key_env} is unset — refusing to deploy an unauthenticated "
            f"{spec.name} endpoint. Set {spec.api_key_env}, or BENCH_ALLOW_NO_AUTH=1 "
            "to intentionally run an open endpoint."
        )


download_image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("huggingface_hub[hf_transfer]>=0.34")
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1"})
)


def serve_image(registry_ref: str) -> modal.Image:
    """The engine's server image, entrypoint cleared so Modal controls the
    process, with `python` symlinked so Modal can detect the interpreter."""
    return (
        modal.Image.from_registry(registry_ref)
        .entrypoint([])
        .run_commands("ln -sf $(which python3) /usr/local/bin/python || true")
    )


def slugify(model_id: str) -> str:
    return model_id.split("/")[-1].lower().replace(".", "-").replace("_", "-")


@dataclass(frozen=True)
class EngineSpec:
    name: str                 # "sglang" | "vllm"
    registry_ref: str         # image ref with a "{tag}" placeholder
    port: int
    health_path: str
    model_env: str            # deploy-side env var carrying the model id
    api_key_env: str          # deploy-side env var carrying the bearer key
    gpu_env: str
    tag_env: str


@dataclass(frozen=True)
class Resolved:
    model_id: str
    cfg: dict[str, Any]
    gpu: str
    tag: str
    startup_s: int
    app_name: str


def resolve(spec: EngineSpec, model_configs: dict[str, dict[str, Any]]) -> Resolved:
    """Deploy-side resolution of the model + serving config from the env.

    Fails loudly for a model that has no config for this engine, rather than
    silently serving it under a default config (which would benchmark the wrong
    parsers / GPU / context)."""
    model_id = os.environ.get(spec.model_env) or next(iter(model_configs))
    if model_id not in model_configs:
        raise KeyError(
            f"no {spec.name} serving config for {model_id!r}; add it to "
            f"MODEL_CONFIGS (configured: {sorted(model_configs)})"
        )
    cfg = model_configs[model_id]
    return Resolved(
        model_id=model_id,
        cfg=cfg,
        gpu=os.environ.get(spec.gpu_env) or str(cfg["gpu"]),
        tag=os.environ.get(spec.tag_env) or str(cfg["image_tag"]),
        startup_s=int(cfg["startup_min"]) * 60,
        app_name=f"soctalk-{spec.name}-{slugify(model_id)}",
    )


def runtime_model_id() -> str:
    """Read in-container: the model baked into the function's runtime secret."""
    return os.environ[RUNTIME_MODEL_ENV]


def runtime_cfg(model_configs: dict[str, dict[str, Any]], model_id: str) -> dict[str, Any]:
    if model_id not in model_configs:
        raise KeyError(f"no serving config for {model_id!r} in-container")
    return model_configs[model_id]


def do_download(model_id: str) -> None:
    """Pre-stage weights into the shared Volume on a cheap CPU box."""
    from huggingface_hub import snapshot_download

    print(f"downloading {model_id} into the volume ...", flush=True)
    snapshot_download(model_id, cache_dir=HF_CACHE_DIR)
    hf_cache.commit()
    print("done", flush=True)


def masked(cmd: list[str]) -> str:
    """Render a launch command for logging with the bearer token redacted."""
    out: list[str] = []
    i = 0
    while i < len(cmd):
        out.append(cmd[i])
        if cmd[i] == "--api-key" and i + 1 < len(cmd):
            out.append("***")
            i += 2
            continue
        i += 1
    return " ".join(out)
