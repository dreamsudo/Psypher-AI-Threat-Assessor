# =============================================================================
#  Psypher AI Threat Assessor  ·  (c) 2026 PsypherLabs  ·  All rights reserved.
#  engine/__main__.py — command-line entry point.
#  Sealed engine core · installed by bootstrap-1-core.sh
# =============================================================================
"""Command-line interface for the Psypher AI Threat Assessor.

Subcommands:
    run        Run an assessment using the configured packs.
    validate   Validate the configuration and packs without touching a target.
"""
from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

from . import __version__
from .core.banner import show_banner
from .core.config import ConfigError, load_config
from .core.loader import discover_probes
from .core.orchestrate import run_assessment


def _configure_logging(*, verbose: bool, quiet: bool) -> logging.Logger:
    """Configure root logging to stderr and return the application logger."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)-7s %(message)s",
        stream=sys.stderr,
    )
    return logging.getLogger("psypher")


def _cmd_run(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Load the configuration and run a full assessment."""
    config = load_config(args.config)
    run_assessment(config, logger=logger)
    return 0


def _cmd_validate(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Validate the configuration and the selected packs, then report a summary."""
    config = load_config(args.config)
    probes = discover_probes(config, logger)
    logger.info(
        "configuration valid: engagement '%s', %d in-scope asset(s), %d probe(s) enabled",
        config.engagement.name,
        len(config.scope.in_scope),
        len(probes),
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="psypher-assess",
        description="Evidence-driven, framework-grounded threat assessment engine.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    parser.add_argument("-q", "--quiet", action="store_true", help="log warnings and errors only")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug-level logging")
    parser.add_argument(
        "-c", "--config", default="assessor.yaml", help="path to the engagement config (default: assessor.yaml)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run an assessment using the configured packs")
    sub.add_parser("validate", help="validate the configuration and packs without running")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        show_banner()

    logger = _configure_logging(verbose=args.verbose, quiet=args.quiet)

    handlers = {"run": _cmd_run, "validate": _cmd_validate}
    try:
        return handlers[args.command](args, logger)
    except ConfigError as exc:
        logger.error("configuration error: %s", exc)
        return 2
    except KeyboardInterrupt:
        logger.error("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
