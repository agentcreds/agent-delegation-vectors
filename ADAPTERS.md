# Writing an adapter

How to check **your** implementation against these vectors. The work product is one
Python file - an *adapter* - that translates eight questions the runner asks into calls
against your code. The runner owns everything else: case selection, hex decoding,
comparison, reporting. That division is deliberate, because two implementations that
both pass should be comparable - neither got to choose which cases ran or what counted
as a pass.

Read [README.md](README.md) first for what passing means. Short version: these are
*agreement* vectors - passing says "this agrees with the reference implementation",
not "this conforms to a standard". Your implementation must already speak the wire
formats; nothing here is sufficient to build one from scratch.

## Step 0 - see a green run

```bash
pip install agentcreds
python runner/run_vectors.py --adapter runner/adapters/agentcreds_adapter.py
```

Do this before writing anything. It proves your Python and the vector files are fine,
and it shows what a full pass looks like - so when your adapter fails, you know the
failure is yours.

## Step 1 - the skeleton

Create `runner/adapters/my_adapter.py`:

```python
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adapter import Action, ChainInfo  # the shared types


class Adapter:
    def verify_credential(self, credential_json: str, anchor_did: str) -> bool:
        raise NotImplementedError
```

Two rules shape everything you write here:

1. **There is no base class.** The runner duck-types. Copy the shape of
   [`agentcreds_adapter.py`](runner/adapters/agentcreds_adapter.py), don't inherit
   anything.
2. **Raising is treated as reject.** If your implementation signals failure by
   exception, catch nothing and let it propagate. If it returns a status, return the
   bool. Never wrap calls in a try/except that converts a crash into `False` *and*
   never convert `False` into an exception - either convention works, mixing them
   hides bugs.

Run the runner now. Every case fails with `NotImplementedError` - that is your
worklist.

The full contract, with the semantics of every method, is in
[`runner/adapter.py`](runner/adapter.py). Keep it open while you work; the rest of
this tutorial is the recommended order and the trap in each method, not a replacement
for those docstrings.

## Step 2 - the methods, in the order that debugs best

Each method builds on the previous ones, so implement and re-run in this order -
a failure then points at the newest code.

**`verify_credential`** - signature check against a `did:key` anchor. The reject case
is a *wrong* anchor, so hardcoding "the" anchor passes accept and fails reject.

**`revocation_lookup`** - verify the signed status list against the anchor **first**,
then answer the index. If the list does not verify, *raise* - an unverified list must
not answer lookups at all. (The status list is a `statuslist+jwt`; the bits are
DEFLATE-compressed, MSB-first.)

**`verify_token`** - the one most implementations get subtly wrong, twice:

- It must be the full **anchor-rooted** check: credential verifies under the anchor,
  token derives from that credential, root hop minted by the credential subject,
  action survives every hop's narrowing. Verifying the chain's *internal integrity*
  alone passes most accepts and accepts things it must not - a chain can be perfectly
  self-consistent and rooted in an anchor you do not trust.
- Every expiry check must be evaluated **as of the `at` argument** (the file's
  `evaluated_at`), never the wall clock. Delegation tokens are capped at one hour by
  design and cannot be minted far-future the way credentials can. If your API has no
  way to inject the verification instant, that is the first thing to add to your
  implementation - not to the adapter.

**`token_chain`** - decode and report depth and the ordered hop DIDs, root first.
This is the only method about what your implementation *exposes* rather than what it
decides. An empty or reordered chain is a real defect even when every accept/reject
passes: audit and policy layers consume the chain.

**`verify_presentation`** - token + credential + proof of possession, as of `at`. The
proof is over the **leaf** key. On a multi-hop chain that is the last delegate, not
the original subject - reaching for the wrong key passes every single-hop case and
fails exactly `presentation_multihop_accept`.

**`verify_rotated_credential`** - `root_did` is the *pinned root*, not the issuing
key; under rotation the relying party does not know the issuer in advance. Implement
the superseded/repudiated distinction carefully: a **superseded** key stays valid
(planned rotation does not invalidate what it signed), a **repudiated** key does not.
Treating the two alike is wrong in one direction or the other, and the vectors carry
both.

**`verify_approver_key_evidence`** - the individual-approver check. The approver key
means nothing by itself; it must be found in the org-anchor-signed *directory*. An
implementation that verifies the evidence signature without consulting the directory
passes the accept case and fails every reject case.

**`verify_through_trust_framework`** - `framework_did` is the *framework* anchor,
not the issuer. Accept only if the config verifies under it **and is current**, the
issuer is a member, the member meets the config's minimum trust level, and the
credential verifies under the member's key. The trust level is easy to read and
forget to enforce.

**`canonicalize`** *(optional)* - RFC 8785 canonical JSON, compared by **string
equality**. Omit the method entirely if your implementation genuinely does not
canonicalize: the runner reports the suite as *not taken*, which is different from
failing it, and it will not fold an untaken suite into a score. Do not omit it to
dodge failures - actions are bound to canonicalized arguments, so a one-escape
difference means your implementation disagrees with its peers about what a token
authorizes, and that disagreement will surface in production as a signature mismatch
a long way from its cause.

## Step 3 - implementations that are not Python

The duck-typed contract is the point: your adapter can be a thin shim over a
subprocess or an HTTP call. The pattern that works:

```python
import json, subprocess

class Adapter:
    def _call(self, op: str, **args) -> dict:
        req = json.dumps({"op": op, **args})
        out = subprocess.run(
            ["./my-verifier", "--vector-mode"],
            input=req, capture_output=True, text=True, check=True,
        )
        return json.loads(out.stdout)

    def verify_token(self, token_cbor, credential_json, anchor_did, action, at):
        resp = self._call(
            "verify_token",
            token_cbor_hex=token_cbor.hex(),
            credential_json=credential_json,
            anchor_did=anchor_did,
            tool=action.tool,
            parameters=action.parameters,
            at=at,
        )
        return resp["ok"]
```

Ship a small `--vector-mode` entry point in your implementation's own language that
reads one JSON request and writes one JSON response. Keep the shim boring: hex in,
verdict out. If the shim needs retries, per-case special-casing, or fix-ups, the
implementation does not agree with the vectors and the run should say so - that is
the same rule the reference adapter holds itself to.

## Step 4 - reading a failing run

Failure patterns map to causes with unusual reliability here:

| signature | almost certainly |
| --- | --- |
| Every **accept** fails, every **reject** passes | You used the wall clock instead of `at`. The score is nonzero and meaningless - the rejects passed for the wrong reason. |
| Single-hop token cases pass, **multi-hop** fail | Multi-hop chains use a different block-signing construction than single-hop; your verifier handles only the latter. |
| All token cases pass, `presentation_multihop_accept` fails | Proof of possession checked against the root subject's key instead of the leaf delegate's. |
| Accepts pass, `*_wrong_anchor` rejects fail | You verified chain integrity but never bound the root to the given anchor. |
| `token_chain` cases fail with correct depth but wrong DIDs | Hop order. `agent_dids` is root-first and order is part of the assertion. |
| Rotation accept passes, repudiation reject fails | Superseded and repudiated keys treated alike. |
| Approver accept passes, every approver reject fails | Evidence signature checked without consulting the directory. |
| jcs cases fail on strings or floats | Escape or number rendering differs from RFC 8785 - check `\uXXXX` policy and shortest-round-trip float form. |
| Cases error with `unknown format` | The file's `format` is newer than your runner checkout. Update the checkout; do **not** patch the runner to skip unknown cases - skipping reports success for checks that never ran. |

## What a pass entitles you to say

28/28 plus the canonicalization suite means: *"our implementation reaches the same
authorization decisions as the AgentCreds reference implementation on these cases,
and canonicalizes identically."* That is a real, useful interoperability claim - it
is what lets a token minted by one side verify on the other. It is not a conformance
claim, because there is no published wire-format standard here to conform to; see
README.md. If that changes, this file changes.

Vectors are regenerated over time and the `format` integer moves when a case gains a
required field or a new kind appears. An adapter needs no changes across
regenerations - only across format bumps, which is when new methods or fields show up
in [`runner/adapter.py`](runner/adapter.py)'s history.
