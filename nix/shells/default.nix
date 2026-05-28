{ pkgs }:

let
  python = pkgs.python311;
  
  # Python packages available from nixpkgs
  pythonWithPackages = python.withPackages (ps: with ps; [
    # Build tools
    pip
    setuptools
    wheel
    hatchling
    
    # Dev tools (available in nixpkgs)
    pytest
    pytest-asyncio
    pytest-cov
    mypy
    
    # Some runtime deps that are in nixpkgs
    pydantic
    python-dotenv
    aiohttp
    rich
    structlog
    fastapi
    uvicorn
    sqlalchemy
    alembic
    psycopg2
    greenlet

    # Type stubs
    types-requests
  ]);

in pkgs.mkShell {
  name = "soctalk-dev";

  buildInputs = [
    # Python with base packages
    pythonWithPackages

    # Node.js and pnpm for frontend
    pkgs.nodejs_20
    pkgs.nodePackages.pnpm

    # PostgreSQL client tools
    pkgs.postgresql_16

    # Testing
    pkgs.playwright-driver.browsers

    # Linting and formatting
    pkgs.ruff
    pkgs.nodePackages.prettier

    # Build tools
    pkgs.gnumake
    pkgs.gcc
    pkgs.pkg-config

    # Runtime dependencies for Python packages
    pkgs.openssl
    pkgs.openssl.dev
    pkgs.postgresql_16.lib
    pkgs.libffi

    # Utilities
    pkgs.curl
    pkgs.jq
    pkgs.git
    pkgs.just

    # Kubernetes tooling (Layer C — multi-tenant local stack on k3d).
    # See scripts/dev-up.sh for the cluster-bring-up procedure these
    # tools drive (k3d cluster + Cilium CNI + cert-manager), and the
    # README "Multi-tenant deployment" section for the architecture.
    # Docker itself is NOT Nix-managed — the host must provide it
    # (Docker Desktop / Colima / native dockerd on Linux).
    pkgs.kubectl
    pkgs.kubernetes-helm
    pkgs.k3d

    # For building MCP servers locally (optional)
    pkgs.rustc
    pkgs.cargo
  ];

  shellHook = ''
    echo "SocTalk Development Shell"
    echo "========================="
    echo ""
    
    # Create virtual environment if it doesn't exist
    if [ ! -d .venv ]; then
      echo "Creating Python virtual environment..."
      python -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Install Python dependencies if needed
    if [ ! -f .venv/.installed ]; then
      echo "Installing Python dependencies..."
      # Temporarily set LD_LIBRARY_PATH for pip install (native deps may need it)
      LD_LIBRARY_PATH="$NIX_LD_LIBRARY_PATH" pip install -e ".[dev,slack]" --quiet
      touch .venv/.installed
    fi
    
    echo "Python: $(python --version)"
    echo "Node.js: $(node --version)"
    echo "pnpm: $(pnpm --version)"
    echo "PostgreSQL client: $(psql --version | head -1)"
    echo "kubectl: $(kubectl version --client -o json 2>/dev/null | jq -r .clientVersion.gitVersion 2>/dev/null || kubectl version --client --short 2>/dev/null | head -1)"
    echo "helm: $(helm version --short 2>/dev/null)"
    echo "k3d: $(k3d version 2>/dev/null | head -1)"
    echo ""
    echo "Commands:"
    echo "  Backend:"
    echo "    pytest -m 'not integration'  # Run unit tests"
    echo "    pytest -m integration        # Run integration tests"
    echo "    ruff check src/              # Lint Python code"
    echo "    alembic upgrade head         # Run migrations"
    echo "    uvicorn soctalk.api.app:app --reload  # Start API server"
    echo ""
    echo "  Frontend:"
    echo "    cd frontend && pnpm install  # Install deps"
    echo "    cd frontend && pnpm dev      # Start dev server"
    echo "    cd frontend && pnpm check    # Type check"
    echo "    cd frontend && pnpm test     # Run Playwright tests"
    echo ""
    echo "  Docker (via just):"
    echo "    just build-api               # Build & load API image"
    echo "    just build-orchestrator      # Build & load orchestrator image"
    echo "    just build-frontend          # Build & load frontend image"
    echo "    just build-all               # Build all images"
    echo "    just run                     # Run all services"
    echo "    just                         # Show all targets"
    echo ""
    echo "  Kubernetes (Layer C, multi-tenant local stack):"
    echo "    ./scripts/dev-up.sh          # Create k3d cluster + Cilium + cert-manager"
    echo "    ./scripts/dev-down.sh        # Tear down the k3d cluster + drop .kube/config"
    echo "    ./scripts/local-up.sh        # Slim k3d (no Cilium) for fast iteration"
    echo "    ./scripts/local-down.sh      # Tear down the local k3d cluster"
    echo "    helm install soctalk-system charts/soctalk-system ...   # Install control plane"
    echo "    kubectl -n soctalk-system get pods                      # Watch boot"
    echo "    kubectl get ns                                          # See tenant-* namespaces"
    echo ""
    echo "  Nix:"
    echo "    nix build .#soctalk-api      # Build API package"
    echo "    nix build .#soctalk-frontend # Build frontend"
    echo "    nix build .#docker-api       # Build API Docker image"
    echo ""

    # Set up Playwright browsers path
    export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"

    # Ensure PYTHONPATH includes src
    export PYTHONPATH="$PWD/src:$PYTHONPATH"

    # PostgreSQL connection defaults (for local dev)
    export DATABASE_URL="''${DATABASE_URL:-postgresql+asyncpg://soctalk:soctalk@localhost:5432/soctalk}"
    
    # OpenSSL for building packages that need it
    export OPENSSL_DIR="${pkgs.openssl.dev}"
    export OPENSSL_LIB_DIR="${pkgs.openssl.out}/lib"
    export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"

    # Make NIX_LD_LIBRARY_PATH effective for every command run inside the
    # dev shell. Scoped to the shell hook (not the mkShell env block) so
    # it does NOT propagate to ``nix`` invocations made from outside the
    # shell. Required for the SQLAlchemy greenlet C extension and any
    # other wheel whose .so has NEEDED libstdc++.so.6. See CONTRIBUTING.md
    # "Working with the Nix dev shell" for the runtime invariant this
    # enforces and for the discipline rule that tools like opencode must
    # be launched from inside this shell. The double-single-quote prefix
    # below is Nix escape syntax to pass the bash parameter-expansion
    # through to the runtime shell verbatim.
    export LD_LIBRARY_PATH="$NIX_LD_LIBRARY_PATH''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  '';

  # Environment variables
  RUST_LOG = "info";
  SOCTALK_LOG_LEVEL = "DEBUG";
  
  # LD_LIBRARY_PATH scope policy:
  #
  # We deliberately set ``LD_LIBRARY_PATH`` inside the ``shellHook`` (above),
  # NOT here in the ``mkShell`` env attribute block. The mkShell variant
  # would bake the var into the derivation, so any process that inherits
  # the dev-shell env — including ``nix`` invocations themselves — would
  # see the foreign libstdc++ on their search path. ``nix`` is a
  # statically-shipped binary that does not tolerate that well.
  #
  # Scoping the export to the shellHook keeps the var out of the
  # derivation while still ensuring every command an engineer runs in
  # the shell (pytest, alembic, the API server, opencode) inherits it
  # and can resolve libstdc++.so.6. ``nix`` from outside this shell is
  # unaffected.
  #
  # ``NIX_LD_LIBRARY_PATH`` (below) is the set of libraries the shellHook
  # turns into ``LD_LIBRARY_PATH``. Add new entries here when a Python
  # wheel's C extension fails to resolve a new NEEDED library.
  NIX_LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
    pkgs.stdenv.cc.cc.lib
    pkgs.openssl
    pkgs.postgresql_16.lib
    pkgs.zlib
  ];
}
