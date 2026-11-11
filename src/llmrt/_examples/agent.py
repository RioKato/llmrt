"""Entry point for the LiteLLM investigation loop.

Run as the installed package via its ``baseagent`` entry point.

Shell.sandbox() exposes host command-line tools read-only while
keeping the chosen directory isolated at /workspace. The directory is read-only
unless an OverlayFS state directory is supplied.
"""

import argparse
import asyncio
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from llmrt import Runtime
from llmrt.tools import Report, Shell

from .recon import run_recon


def main(argv: Sequence[str] | None = None) -> int:
    return asyncio.run(_main(argv))


async def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an LLM tool-calling investigation")
    parser.add_argument("source", type=Path, help="Directory to expose at /workspace")
    parser.add_argument("prompt", help="Initial user prompt")
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
    if overlay_dir is not None:
        upper, work = overlay_dir / "upper", overlay_dir / "work"
        if not upper.is_dir() or not work.is_dir():
            parser.error(f"OverlayFS requires existing upper/ and work/ in: {overlay_dir}")
        if any(work.iterdir()):
            parser.error(f"OverlayFS work directory must be empty: {work}")
        if upper.stat().st_dev != work.stat().st_dev:
            parser.error("OverlayFS upper/ and work/ must be on the same filesystem")

    params: dict[str, Any] = {"model": args.model}
    if args.api_base is not None:
        params["api_base"] = args.api_base
    if args.max_input_tokens is not None:
        params["max_input_tokens"] = args.max_input_tokens
    llm = Runtime(args.workers, **params)

    async def investigate(prompt: str, log: Path | None, overlay: Path | None) -> str:
        shell = Shell().sandbox().workspace(source, "/workspace", overlay_dir=overlay)
        if args.allow_shell_network:
            shell.share_net()
        messages: list[dict[str, Any]] = []
        if args.system is not None:
            messages.append({"role": "system", "content": args.system})
        messages.append({"role": "user", "content": prompt})
        response, context = await llm.ask(messages=messages, tools=[shell, Report(args.reports)])
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a", encoding="utf-8") as file:
                file.write(json.dumps({"event": "run_end", "context": context}, ensure_ascii=False, default=str) + "\n")
        return response.choices[0].message.content or ""

    if not args.auto_focus:
        print(await investigate(args.prompt, args.log, overlay_dir))
        return 0

    print("[recon] Discovering focus areas", file=sys.stderr, flush=True)
    areas = await asyncio.to_thread(
        run_recon,
        source,
        args.model,
        api_base=args.api_base,
        system=args.system,
        max_input_tokens=args.max_input_tokens,
        log=args.reports / "recon.jsonl",
        allow_shell_network=args.allow_shell_network,
    )
    print(f"[recon] Queued {len(areas)} focus areas", file=sys.stderr, flush=True)

    async def run_focus(index: int, focus: str) -> tuple[int, str | None, bool]:
        prompt = args.prompt + (
            "\n\n## Focus area\n"
            f"Concentrate this investigation on: {focus}\n"
            "Begin there. Other investigations can start in different areas, "
            "so avoid duplicate work. Follow relevant connections across "
            "subsystems, and broaden your search if the area is exhausted."
        )
        log = None
        if args.log is not None:
            log = args.log.with_name(f"{args.log.stem}.focus_{index:03d}{args.log.suffix}")
        print(f"[finder {index}] Started: {focus}", file=sys.stderr, flush=True)
        try:
            if overlay_dir is None:
                result = await investigate(prompt, log, None)
            else:
                # Concurrent mounts must not share an OverlayFS upper/work pair.
                with tempfile.TemporaryDirectory(prefix="baseagent-focus-", dir=overlay_dir.parent) as directory:
                    per_focus = Path(directory)
                    await asyncio.to_thread(shutil.copytree, overlay_dir / "upper", per_focus / "upper")
                    (per_focus / "work").mkdir()
                    result = await investigate(prompt, log, per_focus)
        except Exception as exc:
            print(f"[finder {index}] Failed: {exc}", file=sys.stderr, flush=True)
            return index, None, False
        print(f"[finder {index}] Finished", file=sys.stderr, flush=True)
        return index, result, True

    failed = False
    tasks = [run_focus(index, focus) for index, focus in enumerate(areas, 1)]
    for completed in asyncio.as_completed(tasks):
        index, result, succeeded = await completed
        if not succeeded:
            failed = True
        else:
            print(f"[finder {index}] {result}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
