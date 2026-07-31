# Agent delegation interoperability vectors

Golden test vectors for **cross-organizational agent delegation**: signed credentials,
attenuated delegation tokens, proof-of-possession presentations, and revocation status
lists, each paired with the check a relying party must perform and the answer it must
reach.

Point your implementation at `vectors.json`. If it reaches a different `accept`/`reject`
than the file says, the two implementations will not interoperate — and you know that
before you find out in production.

```bash
python runner/run_vectors.py --adapter <your-adapter.py>
```

## Why this exists

Delegation formats fail interoperability in quiet ways. A verifier that decodes a token
but ignores an attenuation hop still returns "valid" — it just returns it for actions the
chain never granted. A verifier that reads a single-hop token correctly can mishandle a
multi-hop one, because multi-hop chains use a different block-signing construction. Prose
specifications do not catch either; a shared set of bytes with expected answers does.

Every case here is a real artifact produced by a working implementation, not a
hand-constructed example. See [SPEC.md](SPEC.md) for the file format and the exact
obligation each case places on a verifier.

## What it covers

| area | cases |
| --- | --- |
| Credential verification against an issuer anchor | accept, wrong-anchor reject |
| Anchor-rooted token authorization | permitted action, denied action |
| **Multi-hop delegation** | accepted after attenuation, rejected for a capability the child narrowed away, plus a control proving the parent still allowed it |
| Presentation (token + credential + proof of possession) | accept, out-of-scope reject, wrong-anchor reject, multi-hop accept |
| Chain shape | delegation depth and the ordered hop identifiers |
| Revocation | signed status list, revoked and clear index lookup |

The multi-hop cases carry the most weight. They exist because a wire-format change that
broke *every* attenuated token once passed a suite whose token cases were all single-hop.

## Running your implementation against them

Implement the five methods in [`runner/adapter.py`](runner/adapter.py) and point the
harness at it. The adapter is the only thing you write; the harness owns case selection,
decoding, comparison and reporting, so your result is comparable with anyone else's —
neither of you got to choose which cases ran or what counted as a pass.

```python
class Adapter:
    def verify_credential(self, credential_json, anchor_did): ...
    def verify_token(self, token_cbor, credential_json, anchor_did, action): ...
    def verify_presentation(self, presentation_cbor, challenge_cbor, anchor_did,
                            action, max_age_secs): ...
    def token_chain(self, token_cbor): ...
    def revocation_lookup(self, list_json, anchor_did, index): ...
```

Each returns a plain bool (or, for `token_chain`, depth plus the ordered hop
identifiers). Raising is treated as "reject", so a verifier that signals failure by
exception needs no special handling.

The harness is standard-library Python and makes no assumption about what it is driving —
an adapter may shell out to another language or call a service over HTTP.

## Reference implementation

[AgentCreds](https://github.com/agentcreds/agentcreds) is the reference implementation and
the source of the artifacts in `vectors.json`.
[`runner/adapters/agentcreds_adapter.py`](runner/adapters/agentcreds_adapter.py) is its
adapter — about forty lines, and the shortest way to see what the harness expects of
yours.

Being the reference implementation confers no authority over what is correct: a case is
correct because SPEC.md says what it asserts and the artifact demonstrably has that
property, not because a particular implementation accepts it. If you believe a case is
wrong, that is a bug report worth filing.

## Relationship to the IETF work

These vectors were built while implementing
[`draft-reece-wimse-cross-org-delegation`](https://datatracker.ietf.org/doc/draft-reece-wimse-cross-org-delegation/).
They are **not** a conformance suite for that draft, and passing them does not constitute
conformance to it: they test wire-format and decision agreement between implementations,
which is narrower than the draft's requirements and does not cover several of them at all.

Where a case does correspond to a requirement, SPEC.md says so — and says what the case
does *not* establish.

## Current status

The reference implementation passes **13/13**.

CI runs the structural validation of `vectors.json` on every push. It does **not** yet run
the reference implementation, because that package is not published to a public index —
the job reports itself as not executed rather than skipping quietly, so a green tick here
never reads as "the reference implementation passes." It starts running automatically once
the package is installable.

## Provenance

`vectors.json` is generated, never hand-edited, by the reference implementation's
`gen_conformance_vectors` example. Keys are random per run, so regeneration rewrites the
artifacts — they are golden *inputs*, not a fixed byte snapshot. The `format` field is the
compatibility signal: a runner should refuse a file whose `format` it does not recognise
rather than silently skipping unknown cases.

Public cryptographic material only — `did:key` identifiers (which encode public keys;
`did:key` cannot represent a private key), signatures, payload hashes and status lists. No
private key or seed appears in this repository.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
