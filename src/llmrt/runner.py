"""Run registered asyncio.Queue consumers concurrently."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


class Runner:
    def __init__(self) -> None:
        self._registered: list[tuple[asyncio.Queue[Any], Callable[[Any], Awaitable[Any]]]] = []

    def register(
        self,
        queue: asyncio.Queue[Any],
        task: Callable[[Any], Awaitable[Any]],
    ) -> None:
        self._registered.append((queue, task))

    async def run(self) -> None:
        async def execute(
            queue: asyncio.Queue[Any],
            task: Callable[[Any], Awaitable[Any]],
            item: Any,
        ) -> None:
            try:
                await task(item)
            finally:
                queue.task_done()

        async def consume(
            queue: asyncio.Queue[Any],
            task: Callable[[Any], Awaitable[Any]],
        ) -> None:
            async with asyncio.TaskGroup() as tasks:
                while True:
                    item = await queue.get()
                    if item is None:
                        queue.task_done()
                        break
                    tasks.create_task(execute(queue, task, item))

        async with asyncio.TaskGroup() as tasks:
            for queue, task in self._registered:
                tasks.create_task(consume(queue, task))
