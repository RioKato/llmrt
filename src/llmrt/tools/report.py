"""Tool for submitting Markdown reports to a queue."""

import asyncio
from typing import Any
from uuid import uuid4


class Report:
    description = {
        "type": "function",
        "function": {
            "name": "report",
            "description": "Submit a finding as a Markdown report. Reporting does not end the investigation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title", "content"],
                "additionalProperties": False,
            },
        },
    }

    def __init__(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._queue = queue

    async def call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        title = arguments["title"]
        content = arguments["content"]
        evidence = arguments.get("evidence", [])

        if not isinstance(title, str) or not title.strip():
            raise ValueError("title must be a nonempty string")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("content must be a nonempty string")
        if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
            raise TypeError("evidence must be a list of strings")

        await self._queue.put({**arguments, "id": uuid4().hex})
        return {"ok": True, "id": report_id}
