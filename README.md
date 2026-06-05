# mylilpwny

> An autonomous pentest and bug bounty friend that operates independently across recon, enumeration, vulnerability analysis, and exploitation — while also serving as a personal security assistant. Extensible, modular, and AI-first from day one.

---

## Quick start

```bash
git clone git@github.com:mushyqt/mylilpwny.git
cd mylilpwny
make install
source .venv/bin/activate
mylilpwny --help
```

## Usage

```bash
# Run the full pipeline (dry-run first to see what would happen)
mylilpwny --target 10.10.10.1 --dry-run run

# Run the full pipeline for real
mylilpwny --target 10.10.10.1 run

# Run a single module
mylilpwny --target 10.10.10.1 scan --module recon
mylilpwny --target 10.10.10.1 scan --module portscan

# Use a scope file (one entry per line: IPs, CIDRs, hostnames, *.wildcards)
mylilpwny --scope-file scope.txt --target 10.10.10.1 run

# Use a custom config
mylilpwny --config /path/to/config.yaml --target 10.10.10.1 run

# Generate a report
mylilpwny report --session <session-id> --format markdown

# Check tool dependencies
mylilpwny check-deps
```

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--target` | `-t` | Target IP, hostname, or CIDR |
| `--scope-file` | | Path to scope file |
| `--config` | `-c` | Path to config.yaml (default: `./config.yaml`) |
| `--dry-run` | | Plan actions without executing anything |
| `--output` | `-o` | Override output directory |
| `--verbose` | `-v` | Enable debug logging |

## Scope file format

```
# Comments are ignored
10.10.10.1
192.168.0.0/24
example.com
*.example.com
```

## Configuration

Edit `config.yaml` to set defaults:

```yaml
mode: semi-auto       # manual | semi-auto | autonomous

rate_limit:
  rps: 10
  max_concurrent_targets: 5

tool_paths:
  nmap: nmap
  masscan: masscan
  # ...

output_dir: output
```

All values can be overridden via CLI flags or env vars (`MYLILPWNY_MODE`, etc.).

## Dev

```bash
make install    # install deps
make test       # run test suite
make lint       # ruff + mypy
make check      # test + lint
```

## Vision

Build a platform in three layers:

- **Tool modules** — subprocess wrappers for external security tools, each independently testable
- **Orchestration engine** — async pipeline with scope enforcement, rate limiting, and state management
- **AI agent loop** — LLM-driven ReAct loop that reasons about findings and decides what to do next

The platform grows from a CLI pentest automation tool into a fully autonomous friend capable of running bug bounty campaigns with minimal human supervision.

## Guiding Principles

- Build bottom-up: Tools → Orchestration → AI
- Every module is independently testable
- The AI layer never calls tools directly — always through the orchestrator
- Scope enforcement and rate limiting are non-negotiable from day one
- Human-in-the-loop gates exist before any destructive or high-risk action
- All findings are persisted — every run builds on the last

## Phases

| Phase | Goal |
|-------|------|
| 1 - Foundation | Working CLI pentest pipeline, no AI |
| 2 - Intelligence | LLM agent wired in, human oversight |
| 3 - Autonomy | Self-improving agent, `--autonomous` mode |
| 4 - Bug Bounty & Assistant | Platform integrations, CSIRT shortcuts |
| 5 - UI | Web dashboard and findings explorer |

## Status

Phase 1 — Sprint 2 in progress.