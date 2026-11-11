"""OverlayFS workspace preparation for Shell tools."""

import asyncio
import shutil
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from .tools import Shell


@asynccontextmanager
async def overlay(shell: Shell, src: Path, dst: Path) -> AsyncIterator[Shell]:
    """Set up an isolated overlay for workspace `src` using `dst/upper`."""
    dst = Path(dst).resolve()
    upper, work = dst / "upper", dst / "work"
    if not upper.is_dir() or not work.is_dir():
        raise ValueError(f"OverlayFS requires existing upper/ and work/ in: {dst}")
    if upper.stat().st_dev != work.stat().st_dev:
        raise ValueError("OverlayFS upper/ and work/ must be on the same filesystem")

    with tempfile.TemporaryDirectory(prefix="overlay-", dir=dst.parent) as directory:
        workspace_overlay = Path(directory)
        await asyncio.to_thread(shutil.copytree, upper, workspace_overlay / "upper")
        (workspace_overlay / "work").mkdir()

        yield shell.workspace(src, "/workspace", overlay_dir=workspace_overlay)
