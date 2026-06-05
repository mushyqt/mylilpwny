# mylilpwny

> An autonomous AI-powered pentest and bug bounty agent that operates independently across recon, enumeration, vulnerability analysis, and exploitation — while also serving as a personal security assistant. Extensible, modular, and AI-first from day one.

## Vision

Build a platform in three layers:

- **Tool modules** — subprocess wrappers for external security tools, each independently testable
- **Orchestration engine** — async pipeline with scope enforcement, rate limiting, and state management
- **AI agent loop** — LLM-driven ReAct loop that reasons about findings and decides what to do next

The platform grows from a CLI pentest automation tool into a fully autonomous agent capable of running bug bounty campaigns with minimal human supervision.

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

Phase 1 in progress.
