"""AXGuard Local-First Security Intelligence API.

Bind localhost by default. No AwareXone cloud. No hosted LLM.
Optional install: pip install 'axguard[api]'
"""

from __future__ import annotations

__all__ = ["__version__", "create_app"]
__version__ = "0.2.0"


def create_app(*args, **kwargs):
    from engines.api.app import create_app as _create_app

    return _create_app(*args, **kwargs)
