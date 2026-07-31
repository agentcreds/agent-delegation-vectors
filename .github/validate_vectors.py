#!/usr/bin/env python3
"""Structural validation of vectors.json against SPEC.md.

Runs before the reference implementation, so a malformed file is reported here rather
than surfacing inside every consumer's adapter where it looks like their bug.

Checks only shape, never cryptography - proving the artifacts verify is the reference
job's business.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_FORMAT = 2

COMMON = {"name", "kind", "anchor_did"}
REQUIRED = {
    "credential": COMMON | {"credential_json", "expect"},
    "token": COMMON | {"credential_json", "token_cbor_hex", "action", "expect"},
    "presentation": COMMON
    | {"presentation_cbor_hex", "challenge_cbor_hex", "action", "max_age_secs", "expect"},
    "token_chain": COMMON | {"token_cbor_hex", "expect_depth", "expect_chain_agent_dids"},
    "revocation": COMMON | {"list_json", "revoked_index", "clear_index"},
}
HEX_FIELDS = ("token_cbor_hex", "presentation_cbor_hex", "challenge_cbor_hex")


def main() -> int:
    errors: "list[str]" = []
    suite = json.loads((ROOT / "vectors.json").read_text(encoding="utf-8"))

    if suite.get("format") != SUPPORTED_FORMAT:
        errors.append(f"format is {suite.get('format')!r}, expected {SUPPORTED_FORMAT}")

    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        print("FAIL: 'cases' must be a non-empty array", file=sys.stderr)
        return 1

    seen: "set[str]" = set()
    for i, c in enumerate(cases):
        name = c.get("name", f"<case {i}>")
        if name in seen:
            errors.append(f"{name}: duplicate case name")
        seen.add(name)

        kind = c.get("kind")
        if kind not in REQUIRED:
            errors.append(f"{name}: unknown kind {kind!r} (SPEC.md defines {sorted(REQUIRED)})")
            continue

        missing = REQUIRED[kind] - set(c)
        if missing:
            errors.append(f"{name}: missing {sorted(missing)}")

        if "expect" in c and c["expect"] not in ("accept", "reject"):
            errors.append(f"{name}: expect must be 'accept' or 'reject', got {c['expect']!r}")

        if not str(c.get("anchor_did", "")).startswith("did:"):
            errors.append(f"{name}: anchor_did is not a DID")

        for f in HEX_FIELDS:
            if f in c:
                try:
                    if not bytes.fromhex(c[f]):
                        errors.append(f"{name}: {f} is empty")
                except ValueError:
                    errors.append(f"{name}: {f} is not valid hex")

        if kind == "token_chain":
            dids = c.get("expect_chain_agent_dids", [])
            if not isinstance(dids, list) or not dids:
                errors.append(f"{name}: expect_chain_agent_dids must be a non-empty array")
            elif len(set(dids)) != len(dids):
                errors.append(f"{name}: chain hops are not distinct")
            # depth is hop count minus the root, so the two must agree or one is wrong.
            elif c.get("expect_depth") != len(dids) - 1:
                errors.append(
                    f"{name}: expect_depth {c.get('expect_depth')} disagrees with "
                    f"{len(dids)} hops (depth should be hops-1)"
                )

        if kind == "revocation" and c.get("revoked_index") == c.get("clear_index"):
            errors.append(f"{name}: revoked_index and clear_index must differ")

    # SPEC.md leans on the multi-hop control; if it ever vanishes the rejection case
    # silently stops proving anything.
    if "token_multihop_reject_attenuated_away" in seen:
        if "token_multihop_parent_allows_before_attenuation" not in seen:
            errors.append(
                "the multi-hop rejection case is present without its control "
                "(token_multihop_parent_allows_before_attenuation) - the rejection "
                "would pass for the wrong reason"
            )

    if errors:
        for e in errors:
            print(f"  FAIL  {e}", file=sys.stderr)
        print(f"\n{len(errors)} problem(s) in vectors.json", file=sys.stderr)
        return 1

    kinds = sorted({c["kind"] for c in cases})
    print(f"vectors.json OK: format {suite['format']}, {len(cases)} cases, kinds {kinds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
