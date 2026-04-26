FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/pof-venv/bin:${PATH}"

# Dépendances système
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        file \
        git \
        libffi-dev \
        libssl-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backends /app/backends
# requirements propre au container angr (lief + capstone + angr qui tire unicorn/claripy/cle…)
COPY docker/decompilers/angr/requirements.txt /app/requirements-container.txt

# Venv Python + angr (inclut capstone, unicorn, claripy, cle, archinfo comme dépendances)
RUN python3 -m venv /opt/pof-venv \
    && /opt/pof-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/pof-venv/bin/pip install --no-cache-dir -r /app/requirements-container.txt

# Utilisateur non-root
RUN useradd -m -u 10001 pof
USER pof

ENTRYPOINT []
CMD ["/opt/pof-venv/bin/python", "-m", "backends.static.decompile", "--list", "--provider", "local"]
