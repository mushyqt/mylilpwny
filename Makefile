UV := uv

.PHONY: install test lint check run

install:
	$(UV) sync

test:
	$(UV) run pytest tests/ -v

lint:
	$(UV) run ruff check mylilpwny/ tests/
	$(UV) run mypy mylilpwny/

check: test lint

run:
	$(UV) run mylilpwny
