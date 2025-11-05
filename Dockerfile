# Dockerfile (place at repo root: async-vuln-scanner/Dockerfile)
FROM python:3.11-slim

# system deps needed for many web libs + Playwright runtime libs if required
RUN apt-get update && apt-get install -y \
    build-essential curl ca-certificates libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libgtk-3-0 libxss1 libasound2 libx11-xcb1 libxcb-dri3-0 libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files into image (ensures pyproject.toml is in /app)
COPY pyproject.toml requirements.txt ./
# copy package code and other files
COPY scanner ./scanner
COPY fetch_render.py ./fetch_render.py
COPY examples ./examples
COPY README.md ./

# create venv and install dependencies & package
RUN python -m venv .venv \
 && . .venv/bin/activate \
 && pip install -U pip setuptools wheel \
 && pip install -r requirements.txt \
 && pip install -e .

# If you need Playwright browsers: uncomment below line in dev builds
# RUN . .venv/bin/activate && python -m playwright install --with-deps

ENV PATH="/app/.venv/bin:${PATH}"

# default entrypoint calls the console script avscan
ENTRYPOINT ["avscan"]
