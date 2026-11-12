"""Async task scheduler with semaphore-based concurrency control."""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

logger = logging.getLogger("marlonthebug.scheduler")


@dataclass
class Task:
    id: str
    coro: Awaitable[Any]
    name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskResult:
    task_id: str
    result: Any = None
    error: Exception | None = None
    success: bool = True


class Scheduler:
    def __init__(self, max_concurrent: int = 50) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self.max_concurrent = max_concurrent
        self.completed: list[TaskResult] = []
        self.running = False

    async def _run_with_semaphore(self, task: Task) -> TaskResult:
        async with self._semaphore:
            try:
                result = await task.coro
                task_result = TaskResult(task_id=task.id, result=result)
            except Exception as e:
                logger.warning("Task %s failed: %s", task.id, e)
                task_result = TaskResult(task_id=task.id, error=e, success=False)
            self.completed.append(task_result)
            return task_result

    async def submit(self, task: Task) -> None:
        if not self.running:
            return
        t = asyncio.create_task(self._run_with_semaphore(task))
        self._tasks[task.id] = t

    async def submit_many(self, tasks: list[Task]) -> None:
        for task in tasks:
            await self.submit(task)

    async def run_all(self, tasks: list[Task]) -> list[TaskResult]:
        self.running = True
        async_tasks = [self._run_with_semaphore(task) for task in tasks]
        results = await asyncio.gather(*async_tasks, return_exceptions=True)
        self.running = False
        return [r if isinstance(r, TaskResult) else TaskResult(task_id="", error=r, success=False) for r in results]

    async def wait_all(self) -> list[TaskResult]:
        if not self._tasks:
            return self.completed
        results = await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self.running = False
        return self.completed

    def cancel_all(self) -> None:
        for task in self._tasks.values():
            task.cancel()
        self._tasks.clear()
        self.running = False
