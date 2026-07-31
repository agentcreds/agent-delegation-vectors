# AgentCreds conformance vectors

Golden test vectors for **cross-organizational agent delegation**: signed credentials,
attenuated delegation tokens, proof-of-possession presentations, and revocation status
lists, each paired with the check a relying party must perform and the answer it must
reach.

Point your implementation at `vectors.json`. If it reaches a different `accept`/`reject`
than the file says, the two implementations will not interoperate — and you know that
before you find out in production.

```bash
python runner/run_vectors.py --adapter runner/adapters/agentcreds_adapter.py
```

## Why this exists

Delegation formats fail interoperability in quiet ways. A verifier that decodes a token
but ignores an attenuation hop still returns "valid" — it just returns it for actions the
chain never granted. A binding that reads a single-hop token correctly can mishandle a
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

## Using it against your own implementation

Implement the five methods in [`runner/adapter.py`](runner/adapter.py) and run the
harness against it. The adapter is the only thing you write; the harness owns case
selection, decoding and reporting, so your result is comparable with anyone else's.

```python
class MyImplementation:
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

[`runner/adapters/agentcreds_adapter.py`](runner/adapters/agentcreds_adapter.py) is a
worked example against the AgentCreds SDK — about forty lines, and the shortest way to
see what the harness expects.

## Relationship to the IETF work

These vectors were built while implementing
[`draft-reece-wimse-cross-org-delegation`](https://datatracker.ietf.org/doc/draft-reece-wimse-cross-org-delegation/).
They are **not** a conformance suite for that draft and reaching `13/13` here does not
constitute conformance to it: the vectors test wire-format and decision agreement between
implementations, which is narrower than the draft's requirements and does not cover
several of them at all.

Where a case does correspond to a requirement, SPEC.md says so, and says what the case
does *not* establish.

## Provenance

`vectors.json` is generated, never hand-edited, by
`agentcreds-core/examples/gen_conformance_vectors.rs` in the
[AgentCreds SDK](https://github.com/agentcreds/agentcreds). Keys are random per run, so
regeneration rewrites the artifacts — they are golden *inputs*, not a fixed byte
snapshot. The `format` field is the compatibility signal: a runner should refuse a file
whose `format` it does not recognise rather than silently skipping unknown cases.

Public cryptographic material only — `did:key` identifiers, signatures, payload hashes
and status lists. No private key or seed appears in this repository.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
