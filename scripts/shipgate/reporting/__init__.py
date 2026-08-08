"""Rendering. Depends on shipgate.models and shipgate.util only — never on authority.

An attestation may be PASSED IN as an argument (so a report can show one), but reporting
never imports the authority package and never constructs an attestation itself.
"""
from . import html, text

render_html = html.render
render_text = text.render

__all__ = ["html", "text", "render_html", "render_text"]
