"""Tool for saving Markdown reports."""

from pathlib import Path
from typing import Any
from uuid import uuid4


class Report:
    description = {
        "type": "function",
        "function": {
            "name": "report",
            "description": "Save a finding as a Markdown report. Reporting does not end the investigation.",
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

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

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

        body = f"# {title}\n\n{content.rstrip()}\n"
        if evidence:
            body += "\n## Evidence\n\n" + "\n".join(f"- {item}" for item in evidence) + "\n"

        self.directory.mkdir(parents=True, exist_ok=True)
        while True:
            report_id = f"R{uuid4().hex[:12]}"
            try:
                with (self.directory / f"{report_id}.md").open("x", encoding="utf-8") as file:
                    file.write(body)
                break
            except FileExistsError:
                continue

        return {"ok": True, "id": report_id}
