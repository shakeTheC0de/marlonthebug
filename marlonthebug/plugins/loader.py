"""Plugin loader — hot-loads plugins with dependency resolution and error isolation."""

import importlib
import logging

from marlonthebug.plugins.base import BasePlugin
from marlonthebug.plugins.registry import PluginRegistry

logger = logging.getLogger("marlonthebug.plugins.loader")


class PluginLoadError(Exception):
    pass


class PluginDependencyError(PluginLoadError):
    pass


class PluginLoader:
    def __init__(self, registry: PluginRegistry) -> None:
        self.registry = registry

    def load_module(self, module_path: str) -> list[type[BasePlugin]]:
        try:
            module = importlib.import_module(module_path)
            plugins: list[type[BasePlugin]] = []

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                    plugins.append(attr)

            for plugin_class in plugins:
                self.registry.register(plugin_class)

            return plugins
        except ImportError as e:
            raise PluginDependencyError(f"Missing dependency for {module_path}: {e}") from e
        except Exception as e:
            raise PluginLoadError(f"Failed to load plugin from {module_path}: {e}") from e

    def load_category(self, category: str) -> int:
        package_path = f"marlonthebug.plugins.{category}"
        try:
            package = importlib.import_module(package_path)
            count = 0
            for _, module_name, _ in importlib.import_module("pkgutil").iter_modules(
                package.__path__, package.__name__ + "."
            ):
                try:
                    self.load_module(module_name)
                    count += 1
                except PluginLoadError as e:
                    logger.warning(str(e))
            return count
        except ImportError:
            logger.warning("Plugin category not found: %s", category)
            return 0

    def load_all(self) -> dict[str, int]:
        categories = ["recon", "web", "auth", "api", "cloud", "cicd", "llm"]
        results: dict[str, int] = {}
        for category in categories:
            results[category] = self.load_category(category)
        total = sum(results.values())
        logger.info("Loaded %d plugins across %d categories", total, len(results))
        return results
