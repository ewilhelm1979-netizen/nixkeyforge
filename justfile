set shell := ["bash", "-euo", "pipefail", "-c"]

default: check

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-features

audit:
    cargo audit

deny:
    cargo deny check

actionlint:
    actionlint .github/workflows/*.yml

secrets:
    bash scripts/run-gitleaks.sh dir nixkeyforge

secrets-history:
    bash scripts/run-gitleaks.sh history nixkeyforge

secrets-test:
    bash scripts/test-gitleaks.sh

check: fmt-check clippy test audit deny actionlint secrets

nix-check:
    nix flake check --print-build-logs
