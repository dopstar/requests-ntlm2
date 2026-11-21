default:
    @just --list

lint: ruff bandit typecheck imports

ruff:
    uv run --locked --no-default-groups --group dev ruff check requests_ntlm2

bandit:
    uv run --locked --no-default-groups --group dev bandit -r requests_ntlm2

typecheck:
    uv run --locked --no-default-groups --group dev basedpyright

imports:
    uv run --locked --no-default-groups --group dev lint-imports --no-cache

test:
    #!/usr/bin/env bash
    set -eu
    if openssl_modules=$(openssl version -m 2>/dev/null); then
        export OPENSSL_CONF="$PWD/tests/openssl-legacy.cnf"
        export OPENSSL_MODULES="$(cut -d '"' -f 2 <<< "$openssl_modules")"
    fi
    uv sync --locked --no-default-groups --group test
    .venv/bin/python -m tests.test_server &
    server_pid=$!
    trap 'kill "$server_pid"; wait "$server_pid" || true' EXIT
    for attempt in {1..20}; do
        if ! kill -0 "$server_pid" 2>/dev/null; then
            echo "The test server exited before it was ready." >&2
            exit 1
        fi
        if ( : </dev/tcp/127.0.0.1/5000 ) 2>/dev/null; then
            break
        fi
        if [ "$attempt" -eq 20 ]; then
            echo "The test server did not start on port 5000." >&2
            exit 1
        fi
        sleep 0.25
    done
    uv run --no-sync --no-default-groups --group test pytest --cov --cov-report=term-missing tests/unit

build:
    uv build --no-sources

publish:
    uv publish
