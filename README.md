# Agent delegation vectors

Golden test artifacts for **cross-organizational agent delegation**: signed credentials,
attenuated delegation tokens, proof-of-possession presentations, and revocation status
lists, each paired with the check a relying party must perform and the answer it must
reach.

They exist to prove that the reference implementation and its language bindings stay
byte-compatible and reach identical authorization decisions - that a token minted through
one surface verifies identically through another, and keeps doing so as the code changes.

```bash
python runner/run_vectors.py --adapter runner/adapters/agentcreds_adapter.py
```

## What these are, and are not

**These are agreement vectors, not conformance vectors.** The distinction is not
pedantic, and it decides what a passing result entitles you to say.

Conformance vectors are derived from a published specification: you implement the spec,
run the vectors, and passing is evidence you implemented it correctly. These are derived
from **one implementation's behavior**. The expected answer in every case is what the
reference implementation does.

The practical consequence: this repository lets you **check** an implementation you
already have. It does not let you **build** one. [SPEC.md](SPEC.md) documents the vector
file format and states precisely what each case asserts, but it does not specify the wire
formats of the artifacts inside - the CBOR envelopes, the delegation-token block layout
and its Datalog conventions, the credential schema. Nothing here is sufficient to write an
independent verifier from scratch.

So passing 28/28 means *"this agrees with the reference implementation"*. It does not mean
*"this conforms to a standard"*, because no such standard is published here to conform to.
If a wire-format specification is published later, these become conformance vectors for it
- and this section should be rewritten when that happens, not before.

## Why they exist

Delegation formats fail interoperability in quiet ways. A verifier that decodes a token
but ignores an attenuation hop still returns "valid" - it just returns it for actions the
chain never granted. A verifier that reads a single-hop token correctly can mishandle a
multi-hop one, because multi-hop chains use a different block-signing construction.
Neither failure is visible from unit tests inside a single implementation; both are
obvious the moment two surfaces are asked the same question about the same bytes.

Every case is a real artifact produced by a working implementation, not a hand-constructed
example.

## What they cover

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

## The adapter seam

The harness drives an implementation through five methods
([`runner/adapter.py`](runner/adapter.py)); it owns case selection, decoding, comparison
and reporting. Nothing an adapter does can change which cases run or what counts as a
pass, so two adapters that both report 28/28 are measured identically.

```python
class Adapter:
    def verify_credential(self, credential_json, anchor_did): ...
    def verify_token(self, token_cbor, credential_json, anchor_did, action): ...
    def verify_presentation(self, presentation_cbor, challenge_cbor, anchor_did,
                            action, max_age_secs): ...
    def token_chain(self, token_cbor): ...
    def verify_rotated_credential(self, key_history_json, credential_json, root_did): ...
    def verify_approver_key_evidence(self, evidence_json, directory_json,
                                     anchor_did, action): ...
    def verify_through_trust_framework(self, config_json, credential_json,
                                       framework_did): ...
    def revocation_lookup(self, list_json, anchor_did, index): ...
```

Each returns a plain bool (or, for `token_chain`, depth plus the ordered hop
identifiers). Raising is treated as "reject", so an implementation that signals failure by
exception needs no wrapper.

The seam is deliberately transport-agnostic - an adapter may shell out to another language
or call a service over HTTP - because the consumers are language bindings over a shared
core, and a new binding should be provable without changing the harness. It is written the
way it is so that an independent implementation *could* be measured identically, should
one ever exist; today none does, for the reason given above.

## Reference implementation

[AgentCreds](https://github.com/agentcreds) is the reference implementation and the
source of every artifact in `vectors.json`.
[`runner/adapters/agentcreds_adapter.py`](runner/adapters/agentcreds_adapter.py) is its
adapter - about forty lines.

Because the vectors are generated from it, its behavior currently *defines* the expected
answers. That is a property of these being agreement vectors, and it is worth stating
plainly rather than dressing up: a case is right because the reference implementation
produced it and SPEC.md records what it asserts. If you believe a case is wrong, that is
a bug report worth filing - but it is a disagreement with an implementation, not with a
specification.

## Relationship to the IETF work

These vectors were built while implementing
[`draft-reece-wimse-cross-org-delegation`](https://datatracker.ietf.org/doc/draft-reece-wimse-cross-org-delegation/).
They are **not** a conformance suite for that draft, and passing them does not constitute
conformance to it: they test wire-format and decision agreement between implementations,
which is narrower than the draft's requirements and does not cover several of them at all.

Where a case does correspond to a requirement, SPEC.md says so - and says what the case
does *not* establish.

## Current status

The reference implementation passes **28/28**.

CI runs the structural validation of `vectors.json` on every push. It does **not** run the
reference implementation, because that package is not published to a public index and
there is no date for when it will be. The job reports itself as not executed rather than
skipping quietly, so a green tick here never reads as "the reference implementation
passes." Should the package become installable, the job picks it up on its own.

## Provenance

`vectors.json` is generated, never hand-edited, by the reference implementation's
`gen_conformance_vectors` example. Keys are random per run, so regeneration rewrites the
artifacts - they are golden *inputs*, not a fixed byte snapshot. The `format` field is the
compatibility signal: a runner should refuse a file whose `format` it does not recognize
rather than silently skipping unknown cases.

Public cryptographic material only - `did:key` identifiers (which encode public keys;
`did:key` cannot represent a private key), signatures, payload hashes and status lists. No
private key or seed appears in this repository.

## License

Apache-2.0. See [LICENSE](LICENSE).
