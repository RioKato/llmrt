"""BaseAgent CLI entry point.

Run as the installed package via its ``baseagent`` entry point.
"""

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from llmrt import Runtime
from llmrt.strategies import FINDER_PROMPT, run_finder, run_recon


def main(argv: Sequence[str] | None = None) -> int:
    return asyncio.run(_main(argv))


async def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an LLM tool-calling investigation")
    parser.add_argument("source", type=Path, help="Directory to expose at /workspace")
    parser.add_argument("prompt", nargs="?", help="Finder prompt (default: built-in prompt)")
    parser.add_argument("--model", required=True, help="LiteLLM model name")
    parser.add_argument("--api-base", help="OpenAI-compatible API base URL")
    parser.add_argument("--overlay-dir", type=Path, help="OverlayFS state directory containing upper/ and work/")
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--log", type=Path, help="JSONL execution log")
    parser.add_argument("--system", help="System message")
    parser.add_argument("--auto-focus", action="store_true", help="Generate Recon focus areas before this investigation")
    parser.add_argument("--workers", type=int, default=4, help="Maximum concurrent LiteLLM API calls (default: 4)")
    parser.add_argument("--max-input-tokens", type=int)
    parser.add_argument("--allow-shell-network", action="store_true", help="Allow shell commands to use the host network namespace")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be positive")

    source = args.source.resolve()
    if not source.is_dir():
        parser.error(f"source is not a directory: {source}")

    overlay_dir = args.overlay_dir.resolve() if args.overlay_dir is not None else None

    params: dict[str, Any] = {"model": args.model}
    if args.api_base is not None:
        params["api_base"] = args.api_base
    if args.max_input_tokens is not None:
        params["max_input_tokens"] = args.max_input_tokens
    llm = Runtime(args.workers, **params)

    if not args.auto_focus:
        print(
            await run_finder(
                llm,
                source,
                args.prompt,
                reports=args.reports,
                log=args.log,
                overlay_dir=overlay_dir,
                system=args.system,
                allow_shell_network=args.allow_shell_network,
            )
        )
        return 0

    print("[recon] Discovering focus areas", file=sys.stderr, flush=True)
    areas = await run_recon(
        llm,
        source,
        system=args.system,
        log=args.reports / "recon.jsonl",
        allow_shell_network=args.allow_shell_network,
    )
    print(f"[recon] Queued {len(areas)} focus areas", file=sys.stderr, flush=True)

    tasks: dict[asyncio.Task[str], int] = {}
    for index, focus in enumerate(areas, 1):
        focus_prompt = (FINDER_PROMPT if args.prompt is None else args.prompt) + (
            "\n\n## Focus area\n"
            f"Concentrate this investigation on: {focus}\n"
            "Begin there. Other investigations can start in different areas, "
            "so avoid duplicate work. Follow relevant connections across "
            "subsystems, and broaden your search if the area is exhausted."
        )
        log = args.log
        if log is not None:
            log = log.with_name(f"{log.stem}.focus_{index:03d}{log.suffix}")
        print(f"[finder {index}] Started: {focus}", file=sys.stderr, flush=True)
        task = asyncio.create_task(
            run_finder(
                llm,
                source,
                focus_prompt,
                reports=args.reports,
                log=log,
                overlay_dir=overlay_dir,
                system=args.system,
                allow_shell_network=args.allow_shell_network,
            )
        )
        tasks[task] = index

    failed = False
    while tasks:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            index = tasks.pop(task)
            try:
                result = task.result()
            except Exception as exc:
                failed = True
                print(f"[finder {index}] Failed: {exc}", file=sys.stderr, flush=True)
            else:
                print(f"[finder {index}] Finished", file=sys.stderr, flush=True)
                print(f"[finder {index}] {result}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
