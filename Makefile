.PHONY: build test fmt fmt-check clippy check run up down logs

build:
	cargo build

test:
	cargo test

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

# Everything CI runs, locally.
check: fmt-check clippy test

# Run the server against a local Postgres (see .env / docker compose up postgres).
run:
	cargo run

# Bring up server + postgres in containers.
up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f server
