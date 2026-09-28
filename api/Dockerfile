# CipherScope API container (repo.md §7, §11).
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY analyzer/ analyzer/
COPY api/ api/
COPY rules/ /rules/

RUN pip install --no-cache-dir -e ".[dev]" || pip install --no-cache-dir -e .

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
