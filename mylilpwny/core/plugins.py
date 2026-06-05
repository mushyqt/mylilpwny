from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from mylilpwny.logging import get_logger
from mylilpwny.modules.base import BaseModule

log = get_logger(__name__)


def _all_subclasses(cls: type) -> set[type]:
    """Recursively collect all concrete subclasses of cls."""
    result: set[type] = set()
    for sub in cls.__subclasses__():
        if not getattr(sub, "__abstractmethods__", None):
            result.add(sub)
        result |= _all_subclasses(sub)
    return result


def load_plugins(plugin_dir: Path | str) -> dict[str, type[BaseModule]]:
    """Import every *.py file in plugin_dir and return a map of name→class.

    Any class that inherits from BaseModule (directly or indirectly) and
    defines a `name` attribute is registered automatically upon import.
    Files that fail to import are skipped with a warning.
    """
    plugin_dir = Path(plugin_dir)
    if not plugin_dir.is_dir():
        log.debug("plugin directory not found — no plugins loaded", path=str(plugin_dir))
        return {}

    before: set[type] = _all_subclasses(BaseModule)

    for py_file in sorted(plugin_dir.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        module_name = f"_plugins.{py_file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                log.warning("could not create spec for plugin", file=str(py_file))
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            log.debug("plugin file imported", file=py_file.name)
        except Exception as exc:
            log.warning("plugin import failed — skipping", file=py_file.name, error=str(exc))

    after: set[type] = _all_subclasses(BaseModule)
    new_classes = after - before

    registry: dict[str, type[BaseModule]] = {}
    for cls in new_classes:
        plugin_name: Any = getattr(cls, "name", None)
        if not isinstance(plugin_name, str) or not plugin_name:
            log.warning("plugin class missing name attribute — skipping", cls=cls.__name__)
            continue
        if plugin_name in registry:
            log.warning("duplicate plugin name — keeping first registered",
                        name=plugin_name, duplicate=cls.__name__)
            continue
        registry[plugin_name] = cls  # type: ignore[assignment]
        log.info("plugin registered", name=plugin_name, cls=cls.__name__)

    return registry
