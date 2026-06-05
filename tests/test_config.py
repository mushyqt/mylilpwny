import pytest
from pathlib import Path
from pydantic import ValidationError

from mylilpwny.config import Config


def test_load_default_config(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("mode: manual\n")
    cfg = Config.load(cfg_file)
    assert cfg.mode == "manual"
    assert cfg.rate_limit.rps == 10
    assert cfg.timeouts.portscan == 300


def test_load_missing_file():
    with pytest.raises(FileNotFoundError):
        Config.load("nonexistent.yaml")


def test_invalid_mode(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("mode: hack-everything\n")
    with pytest.raises(ValidationError):
        Config.load(cfg_file)


def test_invalid_rps(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("rate_limit:\n  rps: -1\n")
    with pytest.raises(ValidationError):
        Config.load(cfg_file)


def test_invalid_scope_file(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("scope_file: /nonexistent/scope.txt\n")
    with pytest.raises(ValidationError):
        Config.load(cfg_file)


def test_valid_scope_file(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("10.0.0.1\n")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"scope_file: {scope}\n")
    cfg = Config.load(cfg_file)
    assert cfg.scope_file == str(scope)


def test_output_dir_created(tmp_path):
    out = tmp_path / "myoutput"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"output_dir: {out}\n")
    cfg = Config.load(cfg_file)
    assert Path(cfg.output_dir).exists()


def test_empty_yaml_uses_defaults(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("")
    cfg = Config.load(cfg_file)
    assert cfg.mode == "semi-auto"
