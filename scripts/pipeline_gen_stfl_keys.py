"""
XMSS/XMSS^MT Stateful Signature Key Pre-Generation Script.

This module provides functionality to pre-generate expensive XMSS and XMSS^MT
stateful signature keys for use in CI/CD pipelines and testing environments.

Background
----------
XMSS (eXtended Merkle Signature Scheme) and XMSS^MT (XMSS Multi-Tree) are
post-quantum stateful signature schemes that can be computationally expensive
to generate, especially for larger tree heights. Pre-generating these keys
significantly reduces test execution time in CI pipelines.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import logging
import os
from sys import stdout
from typing import Any, Iterable

import oqs
import oqs.serialize

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(stdout))


def _mech_to_filename(name: str) -> str:
    """
    Map mechanism name to key filename (keep in sync with CI pipeline).

    Example:
        "XMSS^MT-SHA2_20/4_256" -> "xmssmt-sha2_20_layers_4_256.der"
        "XMSS-SHA2_10_256" -> "xmss-sha2_10_256.der"

    """
    return f"{name.replace('/', '_layers_', 1).lower()}.der"


def _collect_mechanism_names() -> list[str]:
    """Return all enabled XMSS/XMSS^MT stateful signature mechanisms."""
    return [
        name
        for name in oqs.get_enabled_stateful_sig_mechanisms()
        if name.startswith(("XMSS-", "XMSSMT-"))
    ]


def _check_is_expensive(name: str) -> bool:
    """
    Check if the given XMSS/XMSS^MT mechanism is considered expensive to generate.

    Currently, we consider mechanisms with height > 16 as expensive.
    """
    if name.startswith("XMSS-"):
        parts = name.split("-")[1].split("_")
        height = int(parts[1])
        output = int(parts[2])
        return height > 16 or output == 512
    if name.startswith("XMSSMT-"):
        parts = name.split("-")[1].split("_")
        height = int(parts[1].split("/")[0])
        layers = int(parts[1].split("/")[1])
        return (height == 40 and layers == 2) or (height == 60 and layers == 3)
    return False


def get_all_keys_to_generate() -> list[str]:
    """Get a list of all XMSS/XMSS^MT keys that are considered expensive to generate."""
    all_keys: list[str] = _collect_mechanism_names()
    return [name for name in all_keys if _check_is_expensive(name)]


def check_generated_all_keys(out_dir: Path) -> bool:
    """Check if all XMSS/XMSS^MT keys are present in *out_dir*."""
    all_keys: list[str] = get_all_keys_to_generate()

    for name in all_keys:
        key_filename = _mech_to_filename(name)
        key_path = out_dir / key_filename
        if not key_path.exists():
            return False
    return True


def generate_keys(out_dir: Path) -> dict[str, Any]:
    """
    Generate all XMSS/XMSS^MT keys into *out_dir* if they are missing.

    Returns a small stats dict useful for tests:
        {"generated": int, "skipped": int, "total": int, "missing": list[str]}
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    all_keys: list[str] = _collect_mechanism_names()

    # Track existing keys by stem for informational purposes
    existing_keys: set[str] = {p.stem for p in out_dir.glob("*.der")}

    generated = 0
    skipped = 0

    for name in all_keys:
        if not _check_is_expensive(name):
            logger.debug("Skipping %s (does not need to be pre-generated.)", name)
            continue

        key_filename = _mech_to_filename(name)
        key_path = out_dir / key_filename

        if key_path.exists():
            logger.debug("Skipping %s (already exists)", name)
            skipped += 1
            continue

        logger.debug("Generating %s...", name)
        with oqs.StatefulSignature(name) as sig:
            pub = sig.generate_keypair()
            oqs.serialize.serialize_stateful_signature_key(sig, pub, key_path)
        logger.debug("Generated %s", name)
        generated += 1

    total = len(all_keys)
    logger.debug(
        "\n=== Summary ===\nGenerated: %d\nSkipped: %d\nTotal: %d", generated, skipped, total
    )

    missing: list[str] = []
    for name in all_keys:
        key_filename = _mech_to_filename(name)
        key_path = out_dir / key_filename
        if not key_path.exists():
            missing.append(name)

    if missing:
        logger.debug("\nERROR: The following keys could not be generated:")
        for name in missing:
            logger.debug(" - %s", name)

    logger.debug("\nAll %d XMSS/XMSS^MT keys are available in %s.", total, out_dir)
    logger.debug("\nFiles in %s:", out_dir)

    return {
        "generated": generated,
        "skipped": skipped,
        "total": total,
        "missing": missing,
        "existing": sorted(existing_keys),
    }


def _resolve_out_dir(cli_dir: str | None) -> Path:
    """
    Resolve the output directory from CLI argument or KEY_DIR env.

    Precedence:
      1. Explicit CLI argument (if provided).
      2. $KEY_DIR environment variable (if set).
      3. Default "data/xmss_xmssmt_keys" relative to repo root.
    """
    if cli_dir:
        return Path(cli_dir)

    env_dir = os.environ.get("KEY_DIR")
    if env_dir:
        return Path(env_dir)

    return Path("data/xmss_xmssmt_keys")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate XMSS/XMSS^MT stateful signature keys.",
    )
    parser.add_argument(
        "key_dir",
        nargs="?",
        help=(
            "Output directory for keys. "
            "Defaults to $KEY_DIR if set, otherwise data/xmss_xmssmt_keys."
        ),
    )
    parser.add_argument(
        "--check_keys_dir",
        action="store_true",
        help=(
            "If set, do not generate keys; only check whether all required "
            "XMSS/XMSS^MT keys exist in the output directory. Returns 0 if all "
            "keys are present, 1 if any are missing."
        ),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    out_dir = _resolve_out_dir(args.key_dir)

    if args.check_keys_dir:
        # Only check whether all required keys are present; do not generate.
        all_present = check_generated_all_keys(out_dir)
        if all_present:
            logger.debug("All required XMSS/XMSS^MT keys are present in %s", out_dir)
            return 0
        else:
            logger.debug("Some required XMSS/XMSS^MT keys are missing in %s", out_dir)
            return 1

    _ = generate_keys(out_dir)
    return 0


if __name__ == "__main__":
    main()
