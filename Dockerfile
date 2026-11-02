FROM python:3.13-slim

WORKDIR /app

ARG HELM_VERSION=v3.16.4
ARG HELM_SHA256_AMD64=fc307327959aa38ed8f9f7e66d45492bb022a66c3e5da6063958254b9767d179
ARG HELM_SHA256_ARM64=d3f8f15b3d9ec8c8678fbf3280c3e5902efabe5912e2f9fcf29107efbc8ead69

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
        ca-certificates \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
         amd64) helm_arch=amd64; helm_sha=$HELM_SHA256_AMD64 ;; \
         arm64) helm_arch=arm64; helm_sha=$HELM_SHA256_ARM64 ;; \
         *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSL -o /tmp/helm.tgz "https://get.helm.sh/helm-${HELM_VERSION}-linux-${helm_arch}.tar.gz" \
    && echo "${helm_sha}  /tmp/helm.tgz" | sha256sum -c - \
    && tar -xzf /tmp/helm.tgz -C /tmp \
    && mv "/tmp/linux-${helm_arch}/helm" /usr/local/bin/helm \
    && chmod +x /usr/local/bin/helm \
    && rm -rf /tmp/helm.tgz "/tmp/linux-${helm_arch}" /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml uv.lock README.md ./
# The price catalog seed is force-included into the wheel (pyproject), so it
# must be in the build context or the build fails at metadata generation.
COPY data/pricing ./data/pricing
COPY src/soctalk ./src/soctalk
# pyproject declares soctalk_wire + soctalk_entities as packages too, and
# soctalk.core.ir.graph imports soctalk_entities at startup — without these the
# api image builds fine but crashes on boot with
# ``ModuleNotFoundError: No module named 'soctalk_entities'`` (uvicorn can't
# import the app). They must be present before ``pip install .``.
COPY src/soctalk_wire ./src/soctalk_wire
COPY src/soctalk_entities ./src/soctalk_entities
COPY alembic ./alembic
COPY alembic.ini ./
# Tenant + Wazuh charts: bundled into the api image so the controller's
# helm subprocess can apply them without an OCI registry round-trip.
# Operators in production override SOCTALK_TENANT_CHART_REF /
# SOCTALK_WAZUH_CHART_PATH with their own published refs.
COPY charts/soctalk-tenant ./charts/soctalk-tenant
COPY charts/wazuh ./charts/wazuh

# A handful of alembic revision files in the source tree carry mode 0600
# (e.g. ``add_missing_columns.py``). Helm runs the api Pod with
# ``runAsUser: 10001``, so the non-root process can't read those files
# unless we widen the permission bits. Make all source + migrations
# world-readable; directories executable so traversal works.
RUN find /app -type f -exec chmod a+r {} + \
 && find /app -type d -exec chmod a+rx {} +

# Install Python dependencies FROM THE LOCK. A bare ``pip install .`` resolves
# pyproject's ranges afresh at build time, so two builds of the same commit
# can ship different libraries: a fresh build picked up sqlmodel 0.0.48 /
# SQLAlchemy 2.1 against a lock that pins 0.0.38 / 2.0, and the api failed
# every login with "Datetime values must have timezone information". The
# lock is exported to a requirements file (exact versions, no project
# entry) and installed first; the project itself goes in with --no-deps so
# nothing can re-resolve past the lock.
RUN pip install --no-cache-dir 'uv==0.7.*' \
 && uv export --frozen --no-dev --no-emit-project --no-hashes -o /tmp/requirements.txt \
 && pip install --no-cache-dir -r /tmp/requirements.txt \
 && pip install --no-cache-dir --no-deps . \
 && pip uninstall -y uv \
 && rm -f /tmp/requirements.txt

# Expose port
EXPOSE 8000

# Run the API server
CMD ["uvicorn", "soctalk.core.api.app_v1:app", "--host", "0.0.0.0", "--port", "8000"]
