# Code checker/formatter
#
# Pre-requisites
#
# isort
# mypy
# ruff
# uv

src-dir = oqs
tests-dir = tests
examples-dir = examples

.PHONY lint:
lint:
	echo "Running ruff..."
	uv run ruff check --config pyproject.toml --diff $(src-dir) $(tests-dir) $(examples-dir)

.PHONY format:
format:
	echo "Running ruff check with --fix..."
	uv run ruff check --config pyproject.toml --fix --unsafe-fixes $(src-dir) $(tests-dir) $(examples-dir)

	echo "Running ruff..."
	uv run ruff format --config pyproject.toml $(src-dir) $(tests-dir) $(examples-dir)

	echo "Running isort..."
	uv run isort --settings-file pyproject.toml $(src-dir) $(tests-dir) $(examples-dir)

.PHONE mypy:
mypy:
	echo "Running MyPy..."
	uv run mypy --config-file pyproject.toml $(src-dir)

.PHONY outdated:
outdated:
	uv tree --outdated --universal

.PHONY sync:
sync:
	uv sync --extra dev --extra lint
