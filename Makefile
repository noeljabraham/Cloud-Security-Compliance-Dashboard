ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: build db-down db-up dev dev-api dev-web format install lint migrate test

install:
	npm --prefix web ci

db-up:
	docker compose up -d --wait db

db-down:
	docker compose down

migrate: db-up
	cargo run -p cloudsec-api --bin migrate

dev: migrate
	$(MAKE) -j2 dev-api dev-web

dev-api:
	cargo run -p cloudsec-api --bin cloudsec-api

dev-web:
	npm --prefix web run dev

format:
	cargo fmt --all
	npm --prefix web run format

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	npm --prefix web run lint

test:
	cargo test --workspace
	npm --prefix web test

build:
	cargo build --workspace
	npm --prefix web run build

