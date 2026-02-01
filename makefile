VARIANT ?= amd64

PKGDIR    := bpftime
BUILD_DIR := $(PKGDIR)/build

PRESETS := amd64-Release amd64-Debug arm64-Release arm64-Debug

# Default target when no args given
.DEFAULT_GOAL := all

.PHONY: all container $(PRESETS)

ifeq ($(INSIDE_CONTAINER),1)

all: $(PRESETS)

$(PRESETS):
	cd $(PKGDIR) && cmake --workflow --fresh --preset $@
else

$(PRESETS):
	@echo ">>> Running inside builder container: $@ (CLEAN=$(CLEAN))"
	podman-compose -f container/podman-compose.yml run --rm builder \
		$@ $(if $(CLEAN),CLEAN=$(CLEAN))

builder:
	podman-compose -f container/podman-compose.yml build builder

endif
