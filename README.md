# mylilpwny

> An autonomous pentest and bug bounty agent — recon, enumeration, vulnerability analysis, and AI-driven decision-making. Extensible, modular, local-LLM-first.

---

## Requirements

- Python 3.12+
- [`uv`](https://github.com/astral-sh/uv) (package manager)
- External tools: `nmap`, `masscan`, `gobuster`, `searchsploit` (optional but recommended)
- [Ollama](https://ollama.com) with a local model for the AI agent

## Quick start

```bash
git clone git@github.com:mushyqt/mylilpwny.git
cd mylilpwny
make install
source .venv/bin/activate
mylilpwny --help
```

### Ollama setup (GPU recommended)

```bash
# Arch Linux with NVIDIA GPU
sudo pacman -S extra/ollama-cuda   # GPU-accelerated build
sudo systemctl enable --now ollama

ollama pull qwen2.5:7b             # default model (~4.7 GB, fits RTX 3050 4GB)
```

The agent defaults to `qwen2.5:7b` on `http://localhost:11434`. Configure in `config.yaml`:

```yaml
agent:
  model: qwen2.5:7b
  base_url: http://localhost:11434
  max_iterations: 20
  timeout: 300
```

---

## Commands

### `run` — full pipeline

```bash
# Dry-run (no tools executed, LLM loop skipped)
mylilpwny --target 10.10.10.1 --dry-run run

# Full pipeline: recon → portscan → servicenum → vulnanalysis
mylilpwny --target 10.10.10.1 run

# Run specific stages only
mylilpwny --target 10.10.10.1 run --stages recon,portscan

# Skip stages
mylilpwny --target 10.10.10.1 run --skip servicenum

# Resume a previous session
mylilpwny run --resume <session-id>

# Scope from file
mylilpwny --scope-file scope.txt --target 10.10.10.1 run
```

### `agent` — AI ReAct loop

```bash
# Semi-auto (default): confirms high-risk actions
mylilpwny --target 10.10.10.1 agent

# Custom objective
mylilpwny --target 10.10.10.1 agent --objective "identify web entry points"

# Confirmation mode
mylilpwny --target 10.10.10.1 agent --mode manual       # confirm medium+
mylilpwny --target 10.10.10.1 agent --mode autonomous   # confirm critical only

# Dry-run: LLM plans but no tools execute
mylilpwny --target 10.10.10.1 agent --dry-run

# Resume and override iteration limit
mylilpwny agent --resume <session-id> --max-iter 40
```

### Other commands

```bash
mylilpwny report --session <session-id> --format markdown
mylilpwny sessions
mylilpwny log <session-id>
mylilpwny check-deps
mylilpwny version
```

---

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--target` | `-t` | Target IP, hostname, or CIDR |
| `--scope-file` | | Path to scope file (one entry per line) |
| `--config` | `-c` | Path to `config.yaml` (default: `./config.yaml`) |
| `--dry-run` | | Plan without executing |
| `--output` | `-o` | Override output directory |
| `--verbose` | `-v` | Debug logging to console |

---

## Scope file format

```
# Comments are ignored
10.10.10.1
192.168.0.0/24
example.com
*.example.com
```

---

## Configuration

`config.yaml` (full example):

```yaml
mode: semi-auto       # manual | semi-auto | autonomous

rate_limit:
  rps: 10
  max_concurrent_targets: 5

tool_paths:
  nmap: nmap
  masscan: masscan
  gobuster: gobuster
  searchsploit: searchsploit

output_dir: output

agent:
  provider: ollama
  model: qwen2.5:7b
  base_url: http://localhost:11434
  max_iterations: 20
  timeout: 300
```

All values can be overridden via CLI flags or env vars (`MYLILPWNY_MODE`, etc.).

---

## Architecture

```
CLI (typer)
  │
  ├── Orchestrator          async pipeline, scope enforcement, rate limiting
  │     └── Modules         recon / portscan / servicenum / vulnanalysis
  │
  ├── AgentLoop             ReAct: Observe → Think (LLM) → [Gate] → Act
  │     ├── OllamaProvider  local LLM via /api/chat
  │     ├── AgentMemory     short-term notes (current session)
  │     ├── KnowledgeBase   static CVE seed + cross-session DB findings
  │     ├── RiskClassifier  deterministic floor/ceiling for known tools
  │     └── ConfirmationGate interactive prompt before high-risk actions
  │
  └── SessionManager        SQLite via SQLAlchemy — sessions, findings, audit log
```

### Agent tools

| Tool | Risk | Description |
|------|------|-------------|
| `recon` | low | DNS, WHOIS, ASN, subdomain enum |
| `portscan` | medium | masscan + nmap full port sweep |
| `servicenum` | low | nmap -sV -sC service/version detection |
| `vulnanalysis` | low | searchsploit + NVD CVE lookup |
| `remember` | low | Store observation for current session |
| `query_memory` | low | Query knowledge base + historical findings |
| `done` | low | Signal objective complete |

### Confirmation modes

| Mode | Confirms when |
|------|---------------|
| `manual` | risk ≥ medium |
| `semi-auto` | risk ≥ high |
| `autonomous` | risk = critical only |

---

## Dev

```bash
make install    # install deps + venv
make test       # run test suite (324 tests)
make lint       # ruff + mypy
make check      # test + lint
```

---

## Status

Phase 2 — Sprint 7 complete.

- [x] Full recon → portscan → servicenum → vulnanalysis pipeline
- [x] Async orchestrator with scope enforcement and rate limiting
- [x] Structured findings persistence (SQLite)
- [x] AI agent loop (Ollama, qwen2.5:7b, ReAct pattern)
- [x] Agent memory (short-term notes)
- [x] Knowledge base (static CVE seed + cross-session findings)
- [x] Deterministic risk classifier
- [x] Human confirmation gate
- [x] Session resume and audit log
- [x] Markdown + JSON reporting
- [ ] Exploitation modules (Phase 3)
- [ ] Web dashboard (Phase 5)
