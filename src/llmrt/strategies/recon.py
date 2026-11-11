"""Discover attack-surface focus areas for independent BaseAgent runs.

Adapted from Anthropic's defending-code-reference-harness recon stage
(Apache-2.0): https://github.com/anthropics/defending-code-reference-harness
"""

import json
import re
from pathlib import Path
from typing import Any

from llmrt import Runtime
from llmrt.tools import Shell

RECON_PROMPT = """\
You are performing reconnaissance for an authorized source-code security audit.
Your task is to partition the codebase into independently investigable attack
surfaces for multiple vulnerability-finding agents.

Source root: /workspace

Identify approximately 5–15 distinct subsystems that process untrusted input.
Prefer partitions by parser, input format, protocol phase, or other distinct
processing paths. Avoid partitions that are so narrow they describe a single
statement, so broad they cover most of the project, or overlapping enough that
several agents would investigate the same path.

Explore the source tree yourself. Begin with source files and entry points,
then inspect dispatchers, registration tables, format detection, and processing
functions. For each subsystem give a useful function or file pattern and its
relevant operations (such as parsing lengths, allocating objects, decompressing,
or managing state). Do not claim a property that you have not verified in code.

When complete, output exactly one JSON object with a "focus_areas" array of
self-contained strings. Each string will be passed directly to a separate
agent as a starting direction. Use this format:

{
  "focus_areas": [
    "Subsystem (function or file pattern) — relevant operations",
    "Other subsystem (function or file pattern) — relevant operations"
  ]
}

Output valid JSON only: no markdown fences or commentary. A focus area is a
starting point, not a prohibition on following relevant calls into other
subsystems.
"""


def parse_focus_areas(text: str) -> list[str]:
    """Extract the focus areas from Recon's JSON response."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    areas = data.get("focus_areas")
    if not isinstance(areas, list) or not areas or any(not isinstance(area, str) or not area.strip() for area in areas):
        return []
    return [area.strip() for area in areas]


def remap_focus_area(focus_area: str, names: dict[str, str]) -> str:
    """Follow the placeholder -> new identifier mapping used by the overlay."""
    return re.sub(
        r"\b[A-Za-z_][A-Za-z_0-9]*\b",
        lambda match: names.get(match.group(), match.group()),
        focus_area,
    )


async def run_recon(
    llm: Runtime,
    source: str | Path,
    prompt: str | None = None,
    *,
    log: str | Path | None = None,
    system: str | None = None,
    allow_shell_network: bool = False,
) -> list[str]:
    """Run Recon against the original, read-only source tree.

    Recon uses Runtime and the read-only bubblewrap shell, without Report.
    It finishes on the first non-tool answer; tool rounds are not capped.
    """
    shell = Shell().sandbox().workspace(source, "/workspace")
    if allow_shell_network:
        shell.share_net()

    messages: list[dict[str, Any]] = []
    if system is not None:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": RECON_PROMPT if prompt is None else prompt})

    context = await llm.ask(messages=messages, tools=[shell])
    if log is not None:
        path = Path(log)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as file:
            file.write(
                json.dumps(
                    {"event": "run_end", "context": context},
                    ensure_ascii=False,
                    default=str,
                )
                + "\n"
            )

    areas = parse_focus_areas(context[-1]["content"] or "")
    if not areas:
        raise ValueError("Recon did not emit a valid JSON object with nonempty focus_areas")
    return areas
