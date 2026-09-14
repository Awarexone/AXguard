"""Terminal ASCII branding for AXguard."""

from __future__ import annotations

BANNER = r"""
    ╔══════════════════════════════════════════════════╗
    ║                                                  ║
    ║      █████╗ ██╗  ██╗ ██████╗ ██╗   ██╗ █████╗    ║
    ║     ██╔══██╗╚██╗██╔╝██╔════╝ ██║   ██║██╔══██╗   ║
    ║     ███████║ ╚███╔╝ ██║  ███╗██║   ██║███████║   ║
    ║     ██╔══██║ ██╔██╗ ██║   ██║██║   ██║██╔══██║   ║
    ║     ██║  ██║██╔╝ ██╗╚██████╔╝╚██████╔╝██║  ██║   ║
    ║     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ║
    ║                                                  ║
    ║           pre-ship security gate  ·  v0.1        ║
    ╚══════════════════════════════════════════════════╝
"""

BANNER_COMPACT = r"""
  ▄▀█ ▀▄▀ █▀▀ █░█ ▄▀█ █▀█ █▀▄
  █▀█ █░█ █▄█ █▄█ █▀█ █▀▄ █▄▀
  ───────────────────────────
  pre-ship security gate
"""


def print_banner(compact: bool = False) -> None:
    print(BANNER_COMPACT.strip("\n") if compact else BANNER.strip("\n"))
