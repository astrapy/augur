"""Logging helper that uses rich when available."""

from __future__ import annotations

import logging
import os

_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    level = os.environ.get("AUGUR_LOG", "INFO").upper()
    try:
        from rich.logging import RichHandler
        handler: logging.Handler = RichHandler(rich_tracebacks=True, show_path=False)
        fmt = "%(message)s"
    except ImportError:
        handler = logging.StreamHandler()
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, handlers=[handler])
    _configured = True


def get_logger(name: str) -> logging.Logger:
    _configure()
    return logging.getLogger(name)
