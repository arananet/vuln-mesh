FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]"

COPY . .

ENTRYPOINT ["vuln-mesh"]
CMD ["--help"]
