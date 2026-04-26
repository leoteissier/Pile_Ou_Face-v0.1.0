PYTHON ?= python3
VENV ?= backends/.venv
DECOMPILER ?= retdec
# Détection OS : Linux, Darwin (macOS), Windows
UNAME := $(shell $(PYTHON) -c "import platform; print(platform.system())" 2>/dev/null || echo Linux)
# Chemins BIN différenciés Windows/Unix
ifeq ($(UNAME),Windows)
  BIN := $(VENV)/Scripts
else
  BIN := $(VENV)/bin
endif
PIP := $(BIN)/pip
PY := $(BIN)/python

# --- Architecture Docker ---
# Détecte l'architecture hôte (arm64 sur Apple Silicon / Linux ARM, amd64 sinon)
# Peut être surchargé : make decompiler-docker-build PLATFORM=linux/amd64
HOST_ARCH := $(shell uname -m 2>/dev/null || echo x86_64)
ifeq ($(HOST_ARCH),arm64)
  DEFAULT_PLATFORM := linux/arm64
else ifeq ($(HOST_ARCH),aarch64)
  DEFAULT_PLATFORM := linux/arm64
else
  DEFAULT_PLATFORM := linux/amd64
endif
PLATFORM ?= $(DEFAULT_PLATFORM)
# Plateforme multi-arch pour buildx (toujours les deux)
MULTIARCH_PLATFORMS ?= linux/amd64,linux/arm64

EFFECTIVE_PLATFORM := $(PLATFORM)

.PHONY: help venv install pipeline test clean demo demo-elf demo-push-ret capa-rules capa-docker \
        decompiler-docker-build decompiler-docker-list decompiler-docker-build-multiarch \
        decompilers-docker-build decompilers-docker-list decompilers-docker-build-all \
        decompilers-docker-list-all decompilers-docker-build-multiarch-all buildx-setup \
        yara-check yara-test test-features

help:
	@echo "Targets (Linux, macOS, Windows):"
	@echo "  venv       Create virtualenv in $(VENV)"
	@echo "  install    Install Python deps (requirements.txt)"
	@echo "  capa-rules Clone capa-rules (requis pour l'onglet Capa)"
	@echo "  demo       Compile examples/demo_analysis.c (ELF sur Linux, Mach-O sur macOS, etc.)"
	@echo "  demo-elf   Compile un ELF Linux via Docker (pour Capa sur macOS/Windows)"
	@echo "  demo-push-ret  Binaire avec push+ret pour tester le CFG (x86_64 requis)"
	@echo "  capa-docker Run capa via Docker (contournement Mac ARM64)"
	@echo "  decompiler-docker-build DECOMPILER=retdec    Build l'image Docker d'un décompilateur (PLATFORM=$(EFFECTIVE_PLATFORM))"
	@echo "  decompiler-docker-list  DECOMPILER=retdec    Liste les décompilateurs dans l'image ciblée"
	@echo "  decompiler-docker-build-multiarch DECOMPILER=retdec  Build multi-arch (amd64+arm64) via buildx"
	@echo "  decompilers-docker-build-all                 Build toutes les images décompilateurs"
	@echo "  decompilers-docker-build-multiarch-all       Build multi-arch toutes les images (buildx)"
	@echo "  decompilers-docker-list-all                  Liste la dispo de tous les décompilateurs"
	@echo "  decompilers-docker-build                     Alias hérité → build retdec"
	@echo "  decompilers-docker-list                      Alias hérité → list retdec"
	@echo "  buildx-setup             Crée le builder buildx multi-arch (à faire une fois)"
	@echo ""
	@echo "  PLATFORM=$(PLATFORM) (auto-détecté depuis $(HOST_ARCH), effectif: $(EFFECTIVE_PLATFORM))"
	@echo "  RetDec supporte maintenant amd64 et arm64."
	@echo "  Surcharger si besoin: make decompiler-docker-build PLATFORM=linux/amd64"
	@echo "  yara-check Vérifie si YARA est installé (macOS: brew install yara)"
	@echo "  yara-test  Test YARA sur examples/demo_analysis.elf avec examples/test_rules.yar"
	@echo "  pipeline   Run full pipeline (use ARGS=\"...\")"
	@echo "  test       Run all tests (Python + JavaScript)"
	@echo "  test-features  Test des nouvelles features (push+ret, prelude, gaps)"
	@echo "  clean      Remove venv and caches"
	@echo ""
	@echo "Depuis backends/ : make -C .. demo-elf  ou  cd .. && make demo-elf"

yara-check:
	@command -v yara >/dev/null 2>&1 && echo "YARA installé: $$(yara -v 2>/dev/null || yara --version 2>/dev/null || echo OK)" || \
	(echo "YARA non installé. Sur macOS: brew install yara"; echo "Sur Linux: sudo apt install yara"; exit 1)

yara-test: yara-check demo
	@PYTHONPATH=. $(PYTHON) backends/static/yara_scan.py --binary examples/demo_analysis.elf --rules examples/test_rules.yar 2>/dev/null || \
	(echo "Exécutez: make demo puis testez depuis l'extension (onglet Détection > YARA > Parcourir > examples/test_rules.yar)"; exit 1)

capa-rules:
	@if [ ! -d backends/capa-rules ]; then \
		git clone --depth 1 https://github.com/mandiant/capa-rules backends/capa-rules; \
		echo "capa-rules cloné dans backends/capa-rules."; \
	else \
		echo "backends/capa-rules existe déjà."; \
	fi

demo:
	@if [ "$(UNAME)" = "Darwin" ]; then \
		gcc -arch x86_64 -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null || \
		echo "gcc requis. Sur macOS: xcode-select --install"; \
	elif [ "$(UNAME)" = "Windows" ]; then \
		gcc -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null || \
		echo "gcc requis (MinGW/MSYS2). Sur Windows: installez MinGW ou utilisez 'make demo-elf' avec Docker."; \
	else \
		gcc -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null || \
		echo "gcc requis. Sur Linux: sudo apt install build-essential"; \
	fi
	@if [ -f examples/demo_analysis.elf ]; then \
		echo "Binaire: examples/demo_analysis.elf — Ouvre-le dans Pile ou Face."; \
		[ "$(UNAME)" = "Darwin" ] && echo "  (Mach-O sur macOS; Capa ne supporte que ELF/PE. Pour Capa: make demo-elf)"; \
	fi

demo-elf:
	@docker run --rm -v "$$(pwd):/src" -w /src gcc:latest gcc -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null && \
		echo "ELF Linux: examples/demo_analysis.elf (compatible Capa)" || \
		echo "Docker requis. Installez Docker Desktop (macOS/Windows) ou docker.io (Linux)."

demo-push-ret:
	@echo "Compilation push+ret (x86_64)…"
	@PR_O=examples/push_ret_test.o; \
	if [ "$(UNAME)" = "Darwin" ]; then \
		gcc -arch x86_64 -c examples/push_ret_test.s -o $$PR_O 2>/dev/null || clang -arch x86_64 -c examples/push_ret_test.s -o $$PR_O 2>/dev/null; \
	else \
		gcc -c examples/push_ret_test.s -o $$PR_O 2>/dev/null; \
	fi; \
	if [ -f $$PR_O ]; then \
		if [ "$(UNAME)" = "Darwin" ]; then \
			gcc -arch x86_64 -O0 -g -fno-stack-protector -no-pie $$PR_O examples/demo_analysis.c -o examples/demo_push_ret.elf 2>/dev/null || \
			clang -arch x86_64 -O0 -g -fno-stack-protector -no-pie $$PR_O examples/demo_analysis.c -o examples/demo_push_ret.elf 2>/dev/null; \
		else \
			gcc -O0 -g -fno-stack-protector -no-pie $$PR_O examples/demo_analysis.c -o examples/demo_push_ret.elf 2>/dev/null; \
		fi; \
	fi; \
	if [ -f examples/demo_push_ret.elf ]; then \
		echo "Binaire: examples/demo_push_ret.elf (push+ret, x86_64)"; \
	else \
		echo "Échec. Sur macOS ARM64: gcc -arch x86_64 ou clang -arch x86_64 requis."; \
	fi

capa-docker:
	@$(MAKE) capa-rules 2>/dev/null || true
	@docker run --rm -v "$$(pwd):/work" -w /work python:3.12-slim bash -c "pip install -q flare-capa && capa -j /work/examples/demo_analysis.elf -r /work/backends/capa-rules" 2>/dev/null || \
		echo "Usage: make demo-elf && make capa-docker (Docker requis)"

buildx-setup:
	@echo "==> Création du builder buildx multi-arch 'pof-builder'…"
	@docker buildx inspect pof-builder > /dev/null 2>&1 \
		&& echo "  Builder 'pof-builder' existe déjà." \
		|| (docker buildx create --name pof-builder --driver docker-container --bootstrap && \
		    echo "  Builder 'pof-builder' créé avec succès.")
	@docker buildx use pof-builder
	@echo "  Pour vérifier: docker buildx ls"

decompiler-docker-build:
	@echo "==> Building pile-ou-face/decompiler-$(DECOMPILER):latest [$(EFFECTIVE_PLATFORM)]…"
	@docker build --platform $(EFFECTIVE_PLATFORM) \
		-f docker/decompilers/$(DECOMPILER)/Dockerfile \
		-t pile-ou-face/decompiler-$(DECOMPILER):latest \
		.

decompiler-docker-build-multiarch: buildx-setup
	@echo "==> Building multi-arch pile-ou-face/decompiler-$(DECOMPILER) [$(MULTIARCH_PLATFORMS)]…"
	@docker buildx build --platform $(MULTIARCH_PLATFORMS) \
		-f docker/decompilers/$(DECOMPILER)/Dockerfile \
		-t pile-ou-face/decompiler-$(DECOMPILER):latest \
		--push \
		. \
		|| (echo "" && echo "  Note: --push nécessite un registry (Docker Hub / GHCR)." && \
		    echo "  Pour un test local sans push: make decompiler-docker-build PLATFORM=linux/arm64")

decompiler-docker-list:
	@docker run --rm --platform $(EFFECTIVE_PLATFORM) pile-ou-face/decompiler-$(DECOMPILER):latest python -m backends.static.decompile --list --provider local

decompilers-docker-build:
	@echo "==> Alias hérité: utiliser plutôt 'make decompiler-docker-build DECOMPILER=retdec'"
	@$(MAKE) decompiler-docker-build DECOMPILER=retdec

decompilers-docker-list:
	@echo "==> Alias hérité: utiliser plutôt 'make decompiler-docker-list DECOMPILER=retdec'"
	@$(MAKE) decompiler-docker-list DECOMPILER=retdec

# Build toutes les images décompilateurs disponibles
DECOMPILERS_ALL ?= ghidra retdec angr

decompilers-docker-build-all:
	@echo "==> Build de toutes les images [$(PLATFORM)] …"
	@for d in $(DECOMPILERS_ALL); do \
		echo ""; \
		_plat=$(PLATFORM); \
		echo "==> Building pile-ou-face/decompiler-$$d:latest [$$_plat]…"; \
		$(MAKE) decompiler-docker-build DECOMPILER=$$d PLATFORM=$$_plat || echo "  ERREUR build $$d (continuer)"; \
	done
	@echo ""
	@echo "==> Build terminé pour : $(DECOMPILERS_ALL)"

decompilers-docker-build-multiarch-all: buildx-setup
	@echo "==> Build multi-arch de toutes les images [$(MULTIARCH_PLATFORMS)] …"
	@for d in $(DECOMPILERS_ALL); do \
		echo ""; \
		echo "==> Building multi-arch pile-ou-face/decompiler-$$d [$(MULTIARCH_PLATFORMS)]…"; \
		$(MAKE) decompiler-docker-build-multiarch DECOMPILER=$$d MULTIARCH_PLATFORMS=$(MULTIARCH_PLATFORMS) || echo "  ERREUR build multi-arch $$d (continuer)"; \
	done
	@echo ""
	@echo "==> Build multi-arch terminé pour : $(DECOMPILERS_ALL)"

decompilers-docker-list-all:
	@for d in $(DECOMPILERS_ALL); do \
		echo ""; \
		_plat=$(PLATFORM); \
		echo "==> [$$d] décompilateurs dans pile-ou-face/decompiler-$$d:latest [$$_plat]:"; \
		docker image inspect pile-ou-face/decompiler-$$d:latest > /dev/null 2>&1 \
			&& $(MAKE) decompiler-docker-list DECOMPILER=$$d PLATFORM=$$_plat \
			|| echo "  Image non buildée — lance: make decompiler-docker-build DECOMPILER=$$d"; \
	done

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	@if [ -f backends/requirements.txt ]; then \
		$(PIP) install -r backends/requirements.txt; \
	else \
		echo "backends/requirements.txt not found"; \
	fi
	@$(MAKE) capa-rules 2>/dev/null || true

pipeline: venv
	$(PY) backends/dynamic/pipeline/run_pipeline.py $(ARGS)

test: venv
	$(PY) scripts/run-tests-with-summary.py 2>/dev/null || $(PYTHON) scripts/run-tests-with-summary.py

test-features:
	@echo "=== Tests unitaires (push+ret, prelude, gaps) ==="
	@$(PYTHON) -m unittest backends.static.tests.test_cfg backends.static.tests.test_discover_functions -v
	@echo ""
	@echo "Test manuel avec binaire : make demo puis ouvrir dans Pile ou Face."
	@echo "Push+ret sur binaire : make demo-push-ret"

clean:
	rm -rf $(VENV) __pycache__ extension/node_modules extension/coverage extension/.nyc_output
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
