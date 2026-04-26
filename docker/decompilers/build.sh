#!/usr/bin/env bash
# build.sh — wrapper de compatibilité autour du Makefile
# Usage : ./build.sh [ghidra|retdec|angr|all]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="${1:-all}"

echo "⚠️  docker/decompilers/build.sh est conservé pour compatibilité."
echo "   Source de vérité: le Makefile du repo."

if [ "$TARGET" = "all" ]; then
  exec make -C "$REPO_ROOT" decompilers-docker-build-all
fi

exec make -C "$REPO_ROOT" decompiler-docker-build "DECOMPILER=$TARGET"
