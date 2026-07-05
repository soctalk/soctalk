# SocTalk Launchpad build orchestration.
#
#   make            → full binary (frontend + go)
#   make frontend   → build the SPA and stage it for embedding
#   make binary     → go build only (frontend must be staged)
#   make plugins    → rebuild all plugin binaries

FRONTEND_STAGE := cli/internal/httpapi/frontend_build

.PHONY: all frontend binary plugins

all: frontend binary

frontend:
	cd frontend && pnpm install --frozen-lockfile && pnpm build
	rm -rf $(FRONTEND_STAGE).old 2>/dev/null || true
	[ -d $(FRONTEND_STAGE) ] && mv $(FRONTEND_STAGE) $(FRONTEND_STAGE).old || true
	cp -R frontend/build $(FRONTEND_STAGE)
	rm -rf $(FRONTEND_STAGE).old 2>/dev/null || true

binary:
	cd cli && go build -o bin/launchpad ./cmd/launchpad

plugins:
	cd plugins/qemu && go build -o bin/plugin .
	cd plugins/vmware && go build -o bin/plugin .
