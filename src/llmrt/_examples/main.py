"""Queue-driven source-code security audit."""

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from functools import partial
from pathlib import Path
from typing import Any
from uuid import uuid4

from llmrt import Runner, Runtime
from llmrt.tools import Report, Shell

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


VERIFIER_PROMPT = """\
You are conducting authorized security research on the source code at /workspace.
Independently verify the vulnerability claim below. Check its triggering
conditions, attacker control, reachability, and security impact. Look for
checks or invariants that could invalidate the claim. Reproduce it where
feasible; do not assume it is correct or investigate unrelated vulnerabilities.

Use the report tool to record whether the claim is confirmed, rejected, or
inconclusive, with supporting evidence. Distinguish observed facts from
hypotheses.

Vulnerability claim to verify:
"""


async def recon(
    prompt: str,
    *,
    llm: Runtime,
    source: Path,
    finder_queue: asyncio.Queue[tuple[int, str] | None],
    finder_prompt: str | None,
    failures: list[str],
) -> None:
    try:
        print("[recon] Discovering focus areas", file=sys.stderr, flush=True)
        shell = Shell().sandbox().workspace(source, "/workspace")
        context = await llm.ask(messages=[{"role": "user", "content": prompt}], tools=[shell])
        result = context[-1]["content"] or ""
        try:
            data = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            data = None
        areas = data.get("focus_areas") if isinstance(data, dict) else None
        if not isinstance(areas, list) or not areas or any(not isinstance(area, str) or not area.strip() for area in areas):
            raise ValueError("Recon did not emit a valid JSON object with nonempty focus_areas")
        print(f"[recon] Queued {len(areas)} focus areas", file=sys.stderr, flush=True)
        for index, focus in enumerate(areas, 1):
            focus_prompt = (FINDER_PROMPT if finder_prompt is None else finder_prompt) + (
                "\n\n## Focus area\n"
                f"Concentrate this investigation on: {focus.strip()}\n"
                "Begin there. Other investigations can start in different areas, "
                "so avoid duplicate work. Follow relevant connections across "
                "subsystems, and broaden your search if the area is exhausted."
            )
            await finder_queue.put((index, focus_prompt))
    except Exception as exc:
        failures.append("recon")
        print(f"[recon] Failed: {exc}", file=sys.stderr, flush=True)


async def finder(
    item: tuple[int, str],
    *,
    llm: Runtime,
    source: Path,
    overlay_root: Path,
    report_queue: asyncio.Queue[dict[str, Any] | None],
    failures: list[str],
) -> None:
    index, prompt = item
    try:
        print(f"[finder {index}] Started", file=sys.stderr, flush=True)
        overlay_dir = overlay_root / uuid4().hex
        (overlay_dir / "upper").mkdir(parents=True)
        (overlay_dir / "work").mkdir()
        shell = Shell().sandbox().workspace(source, "/workspace", overlay_dir=overlay_dir)
        context = await llm.ask(
            messages=[{"role": "user", "content": prompt}],
            tools=[shell, Report(report_queue)],
        )
        result = context[-1]["content"] or ""
        print(f"[finder {index}] Finished", file=sys.stderr, flush=True)
        print(f"[finder {index}] {result}")
    except Exception as exc:
        failures.append("finder")
        print(f"[finder] Failed: {exc}", file=sys.stderr, flush=True)


async def verifier(
    item: tuple[str, str],
    *,
    llm: Runtime,
    source: Path,
    overlay_root: Path,
    verified_report_queue: asyncio.Queue[dict[str, Any] | None],
    failures: list[str],
) -> None:
    report_id, claim = item
    try:
        print(f"[verifier {report_id}] Started", file=sys.stderr, flush=True)
        overlay_dir = overlay_root / uuid4().hex
        (overlay_dir / "upper").mkdir(parents=True)
        (overlay_dir / "work").mkdir()
        shell = Shell().sandbox().workspace(source, "/workspace", overlay_dir=overlay_dir)
        context = await llm.ask(
            messages=[{"role": "user", "content": VERIFIER_PROMPT + "\n" + claim}],
            tools=[shell, Report(verified_report_queue)],
        )
        result = context[-1]["content"] or ""
        print(f"[verifier {report_id}] Finished", file=sys.stderr, flush=True)
        print(f"[verifier {report_id}] {result}")
    except Exception as exc:
        failures.append("verifier")
        print(f"[verifier] Failed: {exc}", file=sys.stderr, flush=True)


async def save_report(
    report: dict[str, Any],
    *,
    directory: Path,
    next_queue: asyncio.Queue[tuple[str, str] | None] | None = None,
    failures: list[str],
) -> None:
    try:
        body = f"# {report['title']}\n\n{report['content'].rstrip()}\n"
        if report.get("evidence"):
            body += "\n## Evidence\n\n" + "\n".join(f"- {item}" for item in report["evidence"]) + "\n"
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / f"{report['id']}.md").open("x", encoding="utf-8") as file:
            file.write(body)

        if next_queue is not None:
            claim = f"Finding ID: {report['id']}\nTitle: {report['title']}\n\n{report['content']}"
            if report.get("evidence"):
                claim += "\n\nEvidence:\n" + "\n".join(f"- {x}" for x in report["evidence"])
            await next_queue.put((report["id"], claim))
    except Exception as exc:
        label = "report" if next_queue is not None else "verified report"
        failures.append(label)
        print(f"[{label}] Failed: {exc}", file=sys.stderr, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    return asyncio.run(_main(argv))


async def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a source-code security audit")
    parser.add_argument("source", type=Path)
    parser.add_argument("prompt", nargs="?", help="Finder prompt (default: built-in prompt)")
    parser.add_argument("--model", required=True)
    parser.add_argument("--api-base")
    args = parser.parse_args(argv)

    source = args.source.resolve()
    if not source.is_dir():
        parser.error(f"source is not a directory: {source}")

    params: dict[str, Any] = {"model": args.model}
    if args.api_base is not None:
        params["api_base"] = args.api_base
    llm = Runtime(4, **params)
    reports = Path("reports")

    recon_queue: asyncio.Queue[str | None] = asyncio.Queue()
    finder_queue: asyncio.Queue[tuple[int, str] | None] = asyncio.Queue()
    report_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
    verifier_queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue()
    verified_report_queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
    failures: list[str] = []

    overlay_root = Path("overlays")
    runner = Runner()
    runner.register(recon_queue, partial(recon, llm=llm, source=source, finder_queue=finder_queue, finder_prompt=args.prompt, failures=failures))
    runner.register(finder_queue, partial(finder, llm=llm, source=source, overlay_root=overlay_root, report_queue=report_queue, failures=failures))
    runner.register(report_queue, partial(save_report, directory=reports / "found", next_queue=verifier_queue, failures=failures))
    runner.register(verifier_queue, partial(verifier, llm=llm, source=source, overlay_root=overlay_root, verified_report_queue=verified_report_queue, failures=failures))
    runner.register(verified_report_queue, partial(save_report, directory=reports / "verified", failures=failures))

    consumer = asyncio.create_task(runner.run())
    try:
        await recon_queue.put(RECON_PROMPT)
        await recon_queue.join()
        await finder_queue.join()
        await report_queue.join()
        await verifier_queue.join()
        await verified_report_queue.join()
    finally:
        await recon_queue.put(None)
        await finder_queue.put(None)
        await report_queue.put(None)
        await verifier_queue.put(None)
        await verified_report_queue.put(None)
        await consumer

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
