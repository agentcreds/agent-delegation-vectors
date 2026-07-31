#!/usr/bin/env python3
"""Run an implementation against the AgentCreds conformance vectors.

    python runner/run_vectors.py --adapter runner/adapters/agentcreds_adapter.py

The adapter supplies five methods (see adapter.py); everything else - which cases run,
how artifacts decode, what counts as a pass - lives here, so two implementations that both
report 13/13 are actually comparable.

Standard library only. Exit code 0 if every case passed, 1 otherwise.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adapter import Action, ChainInfo  # noqa: E402

# Bump only alongside the generator. Refusing an unknown format is deliberate: silently
# skipping unrecognised cases reports success for checks that never ran.
SUPPORTED_FORMAT = 2

# Cases that only mean something read together. Reporting one without the other invites a
# false conclusion, so the summary calls it out explicitly.
PAIRED = {
    "token_multihop_reject_attenuated_away": "token_multihop_parent_allows_before_attenuation",
}


def load_adapter(path: Path):
    spec = importlib.util.spec_from_file_location("ac_conformance_adapter", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load adapter: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for factory in ("build", "Adapter", "Implementation"):
        obj = getattr(module, factory, None)
        if obj is not None:
            return obj() if callable(obj) else obj
    raise SystemExit(
        f"{path}: expected a `build()` function or an `Adapter` class at module level"
    )


def decided(fn) -> bool:
    """True = accept. An exception is a reject, so an implementation that signals failure
    by raising needs no special handling in its adapter."""
    try:
        return bool(fn())
    except Exception:
        return False


def run_case(impl, c: dict) -> "tuple[bool, str]":
    """Returns (passed, detail)."""
    kind = c["kind"]
    anchor = c["anchor_did"]
    hexf = lambda k: bytes.fromhex(c[k])  # noqa: E731

    if kind == "token_chain":
        try:
            info = impl.token_chain(hexf("token_cbor_hex"))
        except Exception as exc:
            return False, f"token_chain raised: {type(exc).__name__}: {exc}"
        info = ChainInfo(*info) if not isinstance(info, ChainInfo) else info
        if info.depth != c["expect_depth"]:
            return False, f"depth {info.depth}, expected {c['expect_depth']}"
        want = list(c["expect_chain_agent_dids"])
        got = list(info.agent_dids)
        if got != want:
            if sorted(got) == sorted(want):
                return False, "chain hops correct but out of order (order is part of it)"
            if len(got) != len(want):
                return False, f"chain has {len(got)} hops, expected {len(want)}"
            # Same count, different identifiers - name the first divergence, since
            # "2 returned, expected 2" tells the reader nothing.
            i = next(i for i, (g, w) in enumerate(zip(got, want)) if g != w)
            return False, f"chain hop {i} is {got[i]!r}, expected {want[i]!r}"
        return True, f"depth {info.depth}, {len(got)} hops"

    if kind == "revocation":
        try:
            revoked = impl.revocation_lookup(c["list_json"], anchor, c["revoked_index"])
            clear = impl.revocation_lookup(c["list_json"], anchor, c["clear_index"])
        except Exception as exc:
            return False, f"list did not verify: {type(exc).__name__}: {exc}"
        if not revoked:
            return False, f"index {c['revoked_index']} should read revoked"
        if clear:
            # A lookup stuck at "revoked" fails safe but is still broken; only the clear
            # index catches it.
            return False, f"index {c['clear_index']} should read clear"
        return True, "revoked + clear both correct"

    if kind == "credential":
        got = decided(lambda: impl.verify_credential(c["credential_json"], anchor))
    elif kind == "token":
        action = Action(c["action"]["tool"], c["action"].get("parameters", ""))
        got = decided(
            lambda: impl.verify_token(
                hexf("token_cbor_hex"), c["credential_json"], anchor, action
            )
        )
    elif kind == "presentation":
        action = Action(c["action"]["tool"], c["action"].get("parameters", ""))
        got = decided(
            lambda: impl.verify_presentation(
                hexf("presentation_cbor_hex"),
                hexf("challenge_cbor_hex"),
                anchor,
                action,
                c["max_age_secs"],
            )
        )
    else:
        # Never skip. An unknown kind means this runner predates the vectors.
        return False, f"unknown kind {kind!r} - runner is older than the vector file"

    want = c["expect"] == "accept"
    if got == want:
        return True, "accept" if got else "reject"
    return False, f"expected {c['expect']}, got {'accept' if got else 'reject'}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--adapter", required=True, type=Path, help="path to an adapter module")
    ap.add_argument(
        "--vectors",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "vectors.json",
        help="path to vectors.json (default: alongside this repo's root)",
    )
    args = ap.parse_args()

    suite = json.loads(args.vectors.read_text(encoding="utf-8"))
    if suite.get("format") != SUPPORTED_FORMAT:
        print(
            f"vector format {suite.get('format')} is not supported by this runner "
            f"(expects {SUPPORTED_FORMAT}). Update the runner rather than ignoring "
            f"cases it does not understand.",
            file=sys.stderr,
        )
        return 1

    impl = load_adapter(args.adapter)
    results: "dict[str, bool]" = {}

    for c in suite["cases"]:
        ok, detail = run_case(impl, c)
        results[c["name"]] = ok
        print(f"  {'PASS' if ok else 'FAIL'}  {c['name']:52s} {detail}")

    passed = sum(results.values())
    total = len(results)
    print(f"\nRESULT: {passed}/{total} passed")

    # A rejection case that passes while its control fails proves nothing - the rejection
    # could be for the wrong reason entirely. Say so rather than letting the count imply
    # partial credit.
    for case, control in PAIRED.items():
        if results.get(case) and results.get(control) is False:
            print(
                f"\n  WARNING: '{case}' passed but its control '{control}' failed.\n"
                f"  The rejection cannot be attributed to attenuation - treat this as a\n"
                f"  failure, not a partial pass. See SPEC.md."
            )

    if passed != total:
        print("  failed:", ", ".join(n for n, ok in results.items() if not ok))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
