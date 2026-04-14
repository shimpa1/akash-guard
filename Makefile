IMAGE     ?= ghcr.io/shimpa1/akash-guard
TAG       ?= latest
PLATFORM  ?= linux/amd64

# Local overrides — copy local.mk.example to local.mk and set your values.
# local.mk is gitignored and never committed.
-include local.mk

DEV_USER   ?= $(USER)
REMOTE_DIR := /tmp/akash-guard-bpf

.PHONY: all generate build docker push clean logging-deploy _require-dev-vm

all: generate build

## generate: compile tc_egress.c → Go bindings on a Linux dev VM.
## Requires DEV_VM to be set in local.mk or the environment.
generate: _require-dev-vm
	ssh $(DEV_USER)@$(DEV_VM) "mkdir -p $(REMOTE_DIR)/bpf"
	rsync -az bpf/tc_egress.c bpf/gen.go go.mod go.sum $(DEV_USER)@$(DEV_VM):$(REMOTE_DIR)/
	rsync -az --include="*.go" --exclude="*" bpf/ $(DEV_USER)@$(DEV_VM):$(REMOTE_DIR)/bpf/
	ssh $(DEV_USER)@$(DEV_VM) "cd $(REMOTE_DIR) && go generate ./bpf/"
	rsync -az $(DEV_USER)@$(DEV_VM):$(REMOTE_DIR)/bpf/ bpf/

## build: cross-compile the Go binary for linux/amd64 (native Go cross-compile)
build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go build -trimpath -ldflags="-s -w" \
		-o bin/akash-guard ./cmd/akash-guard

## docker: build the container image on the dev VM
docker: _require-dev-vm
	rsync -az --exclude=bin --exclude='.git' . $(DEV_USER)@$(DEV_VM):$(REMOTE_DIR)/full/
	ssh $(DEV_USER)@$(DEV_VM) "cd $(REMOTE_DIR)/full && docker build -t $(IMAGE):$(TAG) ."

## push: push the container image (run from dev VM after docker target)
push: _require-dev-vm
	ssh $(DEV_USER)@$(DEV_VM) "docker push $(IMAGE):$(TAG)"

## logging-deploy: deploy Loki + Fluent Bit + Grafana to the current kubectl context.
logging-deploy:
	bash deploy/logging/install.sh

clean:
	rm -rf bin/
	rm -f bpf/tc_egress_bpf*.go bpf/tc_egress_bpf*.o
	@[ -n "$(DEV_VM)" ] && ssh $(DEV_USER)@$(DEV_VM) "rm -rf $(REMOTE_DIR)" 2>/dev/null || true

_require-dev-vm:
	@[ -n "$(DEV_VM)" ] || { echo "Error: DEV_VM is not set. Copy local.mk.example to local.mk and set DEV_VM."; exit 1; }
