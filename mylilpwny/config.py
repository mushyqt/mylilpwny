from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class RateLimit(BaseModel):
    rps: int = Field(default=10, gt=0)
    max_concurrent_targets: int = Field(default=5, gt=0)


class ToolPaths(BaseModel):
    nmap: str = "nmap"
    masscan: str = "masscan"
    whatweb: str = "whatweb"
    feroxbuster: str = "feroxbuster"
    searchsploit: str = "searchsploit"
    subfinder: str = "subfinder"
    nuclei: str = "nuclei"


class Timeouts(BaseModel):
    recon: int = Field(default=60, gt=0)
    portscan: int = Field(default=300, gt=0)
    servicenum: int = Field(default=120, gt=0)
    vulnanalysis: int = Field(default=60, gt=0)
    default: int = Field(default=60, gt=0)


class AgentConfig(BaseModel):
    provider: Literal["ollama"] = "ollama"
    model: str = "qwen2.5:7b"
    base_url: str = "http://localhost:11434"
    max_iterations: int = Field(default=20, gt=0)
    timeout: float = Field(default=300.0, gt=0)


class Config(BaseModel):
    mode: Literal["manual", "semi-auto", "autonomous"] = "semi-auto"
    agent: AgentConfig = Field(default_factory=AgentConfig)
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    scope_file: str | None = None
    tool_paths: ToolPaths = Field(default_factory=ToolPaths)
    output_dir: str = "output"
    timeouts: Timeouts = Field(default_factory=Timeouts)

    @field_validator("scope_file")
    @classmethod
    def scope_file_must_exist(cls, v: str | None) -> str | None:
        if v is not None and not Path(v).exists():
            raise ValueError(f"scope_file not found: {v}")
        return v

    @field_validator("output_dir")
    @classmethod
    def ensure_output_dir(cls, v: str) -> str:
        Path(v).mkdir(parents=True, exist_ok=True)
        return v

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        with config_path.open() as f:
            data = yaml.safe_load(f) or {}
        return cls.model_validate(data)
