.PHONY: help install test bench run cli audit lint clean docker-build docker-up

help:
	@echo "WEIGHTTRAP — Autonomous AI Control Plane Build Targets:"
	@echo "  make install      - Install Python dependencies"
	@echo "  make test         - Run 32-test automated verification suite"
	@echo "  make bench        - Run 4 scientific empirical benchmarks"
	@echo "  make run          - Launch FastAPI backend and Dashboard (port 8000)"
	@echo "  make audit        - Generate sample RBI MRM Audit Dossier"
	@echo "  make docker-build - Build Docker container image"
	@echo "  make clean        - Clean cache and temporary test artifacts"

install:
	pip install --upgrade pip
	pip install -r requirements.txt

test:
	python run_all_tests.py

bench:
	python benchmarks/run_complete_evaluation.py

run:
	python api.py

audit:
	python cli.py audit --model razorpay_fraud_scorer_v2.1 --output reports/sample_rbi_mrm_dossier.html

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

docker-build:
	docker build -t weighttrap-control-plane:latest .

docker-up:
	docker compose up -d
