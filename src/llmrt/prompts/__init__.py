"""Render prompt templates."""

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

_environment = Environment(
    loader=FileSystemLoader(Path(__file__).parent),
    keep_trailing_newline=True,
)


def render_recon() -> str:
    return _environment.get_template("recon.j2").render()


def render_finder(focus: str | None = None) -> str:
    return _environment.get_template("finder.j2").render(focus=focus.strip() if focus else None)


def render_verifier(claim: dict[str, Any]) -> str:
    return _environment.get_template("verifier.j2").render(claim=claim)
