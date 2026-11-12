"""Plugin registry — discovers and tracks all available plugins."""

import importlib
import logging
import pkgutil

from marlonthebug.plugins.base import BasePlugin

logger = logging.getLogger("marlonthebug.plugins.registry")


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[BasePlugin]] = {}
        self._instances: dict[str, BasePlugin] = {}

    def register(self, plugin_class: type[BasePlugin]) -> None:
        instance = plugin_class()
        key = f"{instance.category}/{instance.name}"
        self._plugins[key] = plugin_class
        self._instances[key] = instance
        logger.debug("Registered plugin: %s v%s", key, instance.version)

    def unregister(self, name: str, category: str) -> None:
        key = f"{category}/{name}"
        self._plugins.pop(key, None)
        self._instances.pop(key, None)

    def get(self, name: str, category: str) -> BasePlugin | None:
        key = f"{category}/{name}"
        return self._instances.get(key)

    def get_class(self, name: str, category: str) -> type[BasePlugin] | None:
        key = f"{category}/{name}"
        return self._plugins.get(key)

    def list_all(self) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {}
        for _key, instance in self._instances.items():
            category = instance.category
            if category not in result:
                result[category] = []
            result[category].append(
                {
                    "name": instance.name,
                    "version": instance.version,
                    "description": instance.description,
                    "author": instance.author,
                }
            )
        return result

    def get_by_category(self, category: str) -> list[BasePlugin]:
        return [instance for key, instance in self._instances.items() if instance.category == category]

    def discover(self, package_path: str = "marlonthebug.plugins") -> int:
        count = 0
        try:
            package = importlib.import_module(package_path)
            for _, name, is_pkg in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
                if is_pkg:
                    self._discover_package(name)
                else:
                    count += self._load_module(name)
        except ModuleNotFoundError:
            logger.warning("Plugin package not found: %s", package_path)
        count = len(self._instances)
        logger.info("Discovered %d plugins", count)
        return count

    def _discover_package(self, package_name: str) -> int:
        count = 0
        try:
            package = importlib.import_module(package_name)
            for _, name, _ in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
                count += self._load_module(name)
        except ModuleNotFoundError:
            pass
        return count

    def _load_module(self, module_name: str) -> int:
        count = 0
        try:
            module = importlib.import_module(module_name)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                    self.register(attr)
                    count += 1
        except Exception as e:
            logger.warning("Failed to load plugin module %s: %s", module_name, e)
        return count
