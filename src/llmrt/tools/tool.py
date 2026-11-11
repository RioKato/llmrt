from typing import Any, Protocol


class Tool(Protocol):
    @property
    def description(self) -> dict[str, Any]: ...

    async def call(self, arguments: dict[str, Any]) -> dict[str, Any]: ...
