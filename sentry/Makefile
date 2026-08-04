# SENTRY — top-level build.
#
# `make verify` is the full check that can run without Docker: every Go service
# compiles, every test suite passes, and the console's prose lint is clean.

VENV    ?= .venv
PY      ?= $(VENV)/bin/python
PIP     ?= $(VENV)/bin/pip
GO      ?= go
VERSION ?= dev

GO_SERVICES := agent ingest honeypot

.PHONY: all setup go-build go-test py-test console-test verify clean

all: setup go-build

setup: $(VENV)
	$(PIP) -q install -e ./core -e ./worker -r api/requirements.txt
	cd console && npm install --silent

$(VENV):
	python3 -m venv $(VENV)

# The agent needs clang with a bpf target; ingest and honeypot are pure Go.
go-build:
	@$(MAKE) -C agent all VERSION=$(VERSION)
	@for s in ingest honeypot; do \
		echo "building $$s"; \
		mkdir -p $$s/bin; \
		(cd $$s && for a in arm64 amd64; do \
			GOOS=linux GOARCH=$$a CGO_ENABLED=0 $(GO) build \
				-ldflags "-X main.version=$(VERSION) -s -w" \
				-o bin/sentry-$$s-linux-$$a ./cmd/sentry-$$s || exit 1; \
		done); \
	done
	@echo "all Go services built for linux/{arm64,amd64}"

go-test:
	@$(MAKE) -C agent test
	@for s in ingest honeypot; do (cd $$s && $(GO) vet ./... && $(GO) test ./... ) || exit 1; done

py-test:
	$(PY) -m pytest -q
	$(PY) -m pytest estate/driver/test_profiles.py -q -p no:cacheprovider --import-mode=importlib

console-test:
	cd console && npx vitest run && node scripts/lint-prose.mjs

# Applies every migration to a throwaway database and asks Alembic what still
# differs from the models. A model changed without a migration fails here rather
# than at a deploy.
.PHONY: migrations-check migrate
migrations-check:
	$(PY) tools/check_migrations.py

# Against the real database. DATABASE_URL decides which one.
migrate:
	$(VENV)/bin/alembic upgrade head

verify: go-build go-test py-test console-test migrations-check
	@echo
	@echo "verify complete — everything that does not require Docker has run"

clean:
	$(MAKE) -C agent clean
	rm -rf ingest/bin honeypot/bin
	find . -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
