FROM ubuntu:24.04

# Ghidra version à télécharger (headless, via GitHub releases)
ARG GHIDRA_VERSION="12.0.4"
ARG GHIDRA_DATE="20260303"
ARG GHIDRA_SHA256="c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120"
ARG GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"

# TARGETARCH est injecté automatiquement par docker buildx (amd64 ou arm64)
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    GHIDRA_USER_PROJECTS=/tmp/ghidra_projects \
    PATH="/opt/pof-venv/bin:/opt/ghidra/support:${PATH}"

# Dépendances système : JDK 21 requis par Ghidra 11+, Python 3, unzip
# + gcc/make pour compiler le binaire decompile sur arm64
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        bison \
        binutils-dev \
        build-essential \
        ca-certificates \
        curl \
        file \
        flex \
        openjdk-21-jdk-headless \
        python3 \
        python3-pip \
        python3-venv \
        unzip \
        wget \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# JAVA_HOME : détection dynamique de l'arch réelle
RUN DPKG_ARCH=$(dpkg --print-architecture) \
    && JH="/usr/lib/jvm/java-21-openjdk-${DPKG_ARCH}" \
    && if [ ! -d "$JH" ]; then \
         JH=$(find /usr/lib/jvm -maxdepth 1 -name 'java-21-openjdk*' -type d | head -1); \
       fi \
    && echo "JAVA_HOME=$JH" >> /etc/environment \
    && echo "export JAVA_HOME=$JH" >> /etc/profile.d/java_home.sh \
    && ln -sfn "$JH" /usr/lib/jvm/java-21-openjdk-current
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-current

# Téléchargement et installation de Ghidra headless
RUN mkdir -p /opt/ghidra-download \
    && wget -q "${GHIDRA_URL}" -O /opt/ghidra-download/ghidra.zip \
    && unzip -q /opt/ghidra-download/ghidra.zip -d /opt/ghidra-tmp \
    && mv /opt/ghidra-tmp/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm -rf /opt/ghidra-download /opt/ghidra-tmp

# ── Binaire decompile pour linux_arm64 ────────────────────────────────────────
#
# Ghidra 12 ne fournit PAS de binaire decompile pour linux_arm64 dans son zip.
# Solution : compiler depuis les sources GitHub (uniquement le sous-projet C++ du décompileur,
# pas tout Ghidra — rapide, ~2 min).
# Sur amd64, le binaire pré-compilé linux_x86_64 est utilisé directement.
#
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

ARG GHIDRA_VERSION
RUN MACHINE=$(uname -m) \
    && echo "==> Machine: $MACHINE" \
    && if [ "$MACHINE" = "aarch64" ] || [ "$MACHINE" = "arm64" ]; then \
        echo "==> [arm64] Compilation decompile depuis les sources GitHub Ghidra…" \
        && git clone --depth 1 --branch "Ghidra_${GHIDRA_VERSION}_build" --no-checkout \
            https://github.com/NationalSecurityAgency/ghidra.git /tmp/ghidra-src \
        && cd /tmp/ghidra-src \
        && git sparse-checkout init --cone \
        && git sparse-checkout set Ghidra/Features/Decompiler/src/decompile/cpp \
        && git checkout \
        && SRC="/tmp/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp" \
        && OUT="/opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm64" \
        && mkdir -p "$OUT" \
        && sed -i 's/-m32//g' "$SRC/Makefile" "$SRC/makefile" 2>/dev/null || true \
        # Ghidra attend le binaire "ghidra_opt" (protocole Java<->native),
        # pas "decomp_opt" qui est la variante console autonome.
        && make -C "$SRC" ghidra_opt -j$(nproc) \
        && ls -la "$SRC/ghidra_opt" \
        && file "$SRC/ghidra_opt" \
        && cp "$SRC/ghidra_opt" "$OUT/decompile" \
        && chmod 755 "$OUT/decompile" \
        && rm -rf /tmp/ghidra-src \
        && echo "✅ decompile linux_arm64 OK"; \
    else \
        echo "==> [x86_64] Binaire decompile pré-compilé linux_x86_64 utilisé"; \
    fi

WORKDIR /app
COPY backends /app/backends
# requirements propre au container ghidra (lief + capstone + pyghidra uniquement)
COPY docker/decompilers/ghidra/requirements.txt /app/requirements-container.txt

# Venv Python + dépendances minimales du container
RUN python3 -m venv /opt/pof-venv \
    && /opt/pof-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/pof-venv/bin/pip install --no-cache-dir -r /app/requirements-container.txt

# Vérification que PyGhidra.jar est bien embarqué dans Ghidra 12+
RUN test -f /opt/ghidra/Ghidra/Features/PyGhidra/lib/PyGhidra.jar \
    && echo "PyGhidra.jar OK"

# Utilisateur non-root + permissions runtime
RUN useradd -m -u 10001 pof \
    && mkdir -p /tmp/ghidra_projects /tmp/pof_work \
    && chmod 1777 /tmp \
    && chown -R pof:pof /tmp/ghidra_projects /tmp/pof_work /home/pof \
    && chown -R root:pof /opt/ghidra \
    && chmod -R g+rX /opt/ghidra \
    # pyghidra écrit dans ces sous-dossiers au premier démarrage
    && chmod -R g+rwX /opt/ghidra/Ghidra/Features/PyGhidra \
    && { chmod -R g+rwX /opt/ghidra/Extensions 2>/dev/null || true; } \
    && chmod g+rwX /opt/ghidra \
    # Le binaire decompile doit être exécutable par pof
    && find /opt/ghidra/Ghidra/Features/Decompiler/os -type f -name "decompile" \
       -exec chmod 755 {} \;

USER pof

ENV GHIDRA_INSTALL_DIR=/opt/ghidra \
    HOME=/home/pof \
    GHIDRA_USER_PROJECTS=/tmp/ghidra_projects \
    JAVA_OPTS="-Djava.awt.headless=true -Xmx2g"

ENTRYPOINT []
CMD ["/opt/pof-venv/bin/python", "-m", "backends.static.decompile", "--list", "--provider", "local"]
