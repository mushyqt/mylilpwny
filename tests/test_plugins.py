import textwrap
from pathlib import Path
from typing import Any

import pytest

from mylilpwny.core.plugins import load_plugins
from mylilpwny.modules.base import BaseModule, ModuleResult
from mylilpwny.core.state import Target


# --- helpers ---

def _write_plugin(tmp_path: Path, filename: str, source: str) -> Path:
    f = tmp_path / filename
    f.write_text(textwrap.dedent(source))
    return f


# --- tests ---

def test_load_plugins_empty_dir(tmp_path):
    result = load_plugins(tmp_path)
    assert result == {}


def test_load_plugins_missing_dir(tmp_path):
    result = load_plugins(tmp_path / "nonexistent")
    assert result == {}


def test_load_plugins_registers_valid_module(tmp_path):
    _write_plugin(tmp_path, "hello.py", """
        from mylilpwny.modules.base import BaseModule, ModuleResult
        from mylilpwny.core.state import Target
        from typing import Any

        class HelloModule(BaseModule):
            name = "hello"
            description = "test plugin"
            risk_level = "low"

            async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
                return ModuleResult(
                    status="success", raw_output="", parsed_findings=[], duration=0.0
                )
    """)
    result = load_plugins(tmp_path)
    assert "hello" in result
    assert result["hello"].__name__ == "HelloModule"


def test_load_plugins_skips_broken_file(tmp_path):
    _write_plugin(tmp_path, "broken.py", "this is not valid python !!!")
    result = load_plugins(tmp_path)
    assert result == {}


def test_load_plugins_skips_class_without_name(tmp_path):
    _write_plugin(tmp_path, "noname.py", """
        from mylilpwny.modules.base import BaseModule, ModuleResult
        from mylilpwny.core.state import Target
        from typing import Any

        class NoNameModule(BaseModule):
            description = "missing name"
            risk_level = "low"

            async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
                return ModuleResult(
                    status="success", raw_output="", parsed_findings=[], duration=0.0
                )
    """)
    result = load_plugins(tmp_path)
    assert result == {}


def test_load_plugins_skips_underscore_files(tmp_path):
    _write_plugin(tmp_path, "_private.py", """
        from mylilpwny.modules.base import BaseModule, ModuleResult
        from mylilpwny.core.state import Target
        from typing import Any

        class PrivateModule(BaseModule):
            name = "private"
            description = "should not load"
            risk_level = "low"

            async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
                return ModuleResult(
                    status="success", raw_output="", parsed_findings=[], duration=0.0
                )
    """)
    result = load_plugins(tmp_path)
    assert "private" not in result


def test_load_plugins_multiple_plugins(tmp_path):
    for module_name in ("alpha", "beta"):
        _write_plugin(tmp_path, f"{module_name}.py", f"""
            from mylilpwny.modules.base import BaseModule, ModuleResult
            from mylilpwny.core.state import Target
            from typing import Any

            class {module_name.capitalize()}Module(BaseModule):
                name = "{module_name}"
                description = "test"
                risk_level = "low"

                async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
                    return ModuleResult(
                        status="success", raw_output="", parsed_findings=[], duration=0.0
                    )
        """)
    result = load_plugins(tmp_path)
    assert "alpha" in result
    assert "beta" in result
    assert len(result) >= 2


def test_load_plugins_returns_instantiable_class(tmp_path):
    _write_plugin(tmp_path, "greet.py", """
        from mylilpwny.modules.base import BaseModule, ModuleResult
        from mylilpwny.core.state import Target
        from typing import Any

        class GreetModule(BaseModule):
            name = "greet"
            description = "greet plugin"
            risk_level = "low"

            async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
                return ModuleResult(
                    status="success", raw_output="hello", parsed_findings=[], duration=0.0
                )
    """)
    result = load_plugins(tmp_path)
    instance = result["greet"]()
    assert isinstance(instance, BaseModule)
    assert instance.name == "greet"
