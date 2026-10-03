# CipherScope MVP workflows (docs/repo.md §10). Every workflow is one command.

SHELL := /bin/bash
PROFILES ?= all
TRAFFIC ?= icmp,web
PYTHON ?= uv run python

.PHONY: setup lab-up lab-down lab-run lab-all dataset train train-cached eval threat-train threat-benchmark up down analyze test e2e demo

setup:            ## Install Python deps (uv sync), web deps (pnpm i), pull images
	uv sync
	cd web && pnpm i
	docker compose -f docker-compose.yml pull || true

lab-up:           ## Start the strongSwan lab (docker-compose.lab.yml)
	docker compose -f docker-compose.lab.yml --profile transport build
	docker compose -f docker-compose.yml build capture
	docker compose -f docker-compose.lab.yml --profile transport stop transport-client transport-server
	docker compose -f docker-compose.yml stop capture
	docker compose -f docker-compose.lab.yml up -d
	docker compose -f docker-compose.yml up -d --no-deps --force-recreate capture

lab-down:         ## Stop the strongSwan lab
	docker compose -f docker-compose.lab.yml down

lab-run: lab-up  ## Run selected profiles and capture labeled sessions
	$(PYTHON) -m lab.runner run --profiles $(PROFILES) --traffic $(TRAFFIC)

lab-all: lab-up  ## Run lab/matrix.yaml (every profile x every traffic type x repetitions)
	$(PYTHON) -m lab.runner run --matrix lab/matrix.yaml

dataset:          ## Build verified IPsec SA/window Parquet and labels.csv
	$(PYTHON) -m ml.build_dataset

train: dataset    ## Rebuild from saved sessions, then train and gate six IPsec models
	$(PYTHON) -m ml.train

train-cached:     ## Retrain from existing Parquet without rescanning saved captures
	$(PYTHON) -m ml.train

eval:             ## Summarize held-out metrics and update model_card.md
	$(PYTHON) -m ml.evaluate

up:               ## Start api + web + grafana + capture
	docker compose -f docker-compose.yml up -d

down:             ## Stop api + web + capture
	docker compose -f docker-compose.yml down

analyze:          ## CLI analysis without the dashboard: make analyze PCAP=path
	$(PYTHON) -m analyzer.cli $(PCAP) --out data/reports/

test:             ## ruff + pytest (unit + integration)
	$(PYTHON) -m ruff check analyzer api capture lab ml models tests scripts
	$(PYTHON) -m pytest tests/unit tests/integration

e2e:              ## Playwright dashboard test
	cd web && pnpm e2e

demo:             ## Seed demo data and open the dashboard
	$(PYTHON) scripts/seed_demo_data.py
	docker compose -f docker-compose.yml up -d
	@echo "Dashboard: http://localhost:3000"
	@echo "Grafana SOC: http://localhost:3001 (admin / see GF_SECURITY_ADMIN_PASSWORD)"

threat-train:     ## Train threat models from dataset/threats/*.parquet
	$(PYTHON) -m ml.train_threats

threat-benchmark: ## Measure passive threat processor throughput
	$(PYTHON) -m scripts.benchmark_threats
