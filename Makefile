# CipherScope MVP workflows (docs/repo.md §10). Every workflow is one command.

SHELL := /bin/bash
PROFILES ?= all
TRAFFIC ?= icmp,web

.PHONY: setup lab-up lab-down lab-run lab-all dataset train eval up down analyze test e2e demo

setup:            ## Install Python deps (uv sync), web deps (pnpm i), pull images
	uv sync
	cd web && pnpm i
	docker compose -f docker-compose.yml pull || true

lab-up:           ## Start the strongSwan lab (docker-compose.lab.yml)
	docker compose -f docker-compose.lab.yml up -d

lab-down:         ## Stop the strongSwan lab
	docker compose -f docker-compose.lab.yml down

lab-run:          ## Run selected profiles and capture labeled sessions
	python -m lab.runner run --profiles $(PROFILES) --traffic $(TRAFFIC)

lab-all:          ## Run lab/matrix.yaml (every profile x every traffic type x repetitions)
	python -m lab.runner run --matrix lab/matrix.yaml

dataset:          ## Build Parquet features, labels.csv, and grouped splits
	python ml/build_dataset.py

train:            ## Train and calibrate all models into models/
	python ml/train.py

eval:             ## Metrics + figures + update model_card.md
	python ml/evaluate.py

up:               ## Start api + web + capture
	docker compose -f docker-compose.yml up -d

down:             ## Stop api + web + capture
	docker compose -f docker-compose.yml down

analyze:          ## CLI analysis without the dashboard: make analyze PCAP=path
	python -m analyzer.cli $(PCAP) --out data/reports/

test:             ## ruff + pytest (unit + integration)
	ruff check .
	pytest tests/unit tests/integration

e2e:              ## Playwright dashboard test
	cd web && pnpm e2e

demo:             ## Seed demo data and open the dashboard
	python scripts/seed_demo_data.py
	docker compose -f docker-compose.yml up -d
	@echo "Dashboard: http://localhost:3000"
