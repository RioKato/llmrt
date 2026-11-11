"""Run Finder investigations using a shared llmrt Runtime."""

import asyncio
import json
import shutil
import tempfile
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from llmrt import Runtime
from llmrt.tools import Report, Shell, Tool

# Adapted to a generic source-code audit from Anthropic's reference Finder prompt.
FINDER_PROMPT = """\
You are conducting authorized security research on the source code at /workspace.
Your task is to find real security vulnerabilities.

Explore the source and understand how untrusted inputs reach security-sensitive
operations. Investigate suspicious behavior, establish whether it is reachable,
and verify candidate findings using source evidence or reproducible tests where
possible. Prioritize vulnerabilities with meaningful security impact over crashes
that are merely clean error handling or simple denial of service.

When you validate a finding, use the report tool to save a Markdown report with
its impact, triggering conditions, supporting evidence, and reproduction steps
where available. Reporting a finding does not end the investigation; continue
searching for other vulnerabilities.
"""


async def run_finder(
    llm: Runtime,
    source: Path,
    prompt: str | None = None,
    *,
    reports: Path,
    tools: Sequence[Tool] = (),
    log: Path | None = None,
    overlay_dir: Path | None = None,
    system: str | None = None,
    allow_shell_network: bool = False,
) -> str:
    with ExitStack() as stack:
        workspace_overlay = None
        if overlay_dir is not None:
            overlay = Path(overlay_dir).resolve()
            upper, work = overlay / "upper", overlay / "work"
            if not upper.is_dir() or not work.is_dir():
                raise ValueError(f"OverlayFS requires existing upper/ and work/ in: {overlay}")
            if any(work.iterdir()):
                raise ValueError(f"OverlayFS work directory must be empty: {work}")
            if upper.stat().st_dev != work.stat().st_dev:
                raise ValueError("OverlayFS upper/ and work/ must be on the same filesystem")

            # Each invocation gets its own upper/work pair, including concurrent Finders.
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="baseagent-focus-", dir=overlay.parent))
            workspace_overlay = Path(directory)
            await asyncio.to_thread(shutil.copytree, upper, workspace_overlay / "upper")
            (workspace_overlay / "work").mkdir()

        shell = Shell().sandbox().workspace(source, "/workspace", overlay_dir=workspace_overlay)
        if allow_shell_network:
            shell.share_net()

        messages: list[dict[str, Any]] = []
        if system is not None:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": FINDER_PROMPT if prompt is None else prompt})

        context = await llm.ask(messages=messages, tools=[shell, Report(reports), *tools])
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a", encoding="utf-8") as file:
                file.write(
                    json.dumps(
                        {"event": "run_end", "context": context},
                        ensure_ascii=False,
                        default=str,
                    )
                    + "\n"
                )
        return context[-1]["content"] or ""
