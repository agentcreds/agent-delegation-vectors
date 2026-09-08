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

Checking a different implementation means writing an adapter - one Python file, eight
methods, subprocess-friendly for implementations in other languages.
**[ADAPTERS.md](ADAPTERS.md)** is the step-by-step tutorial, including the failure
signatures and what each one means.

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

## The second suite: canonicalization

`jcs_vectors.json` is a separate, independently versioned suite of 16 cases. Each gives a
JSON value and the exact RFC 8785 canonical string an implementation must emit for it -
string equality, not JSON equivalence.

It is here because the delegation suite structurally cannot catch what it tests. Actions
are bound to *canonicalized* arguments, so two implementations that canonicalize
differently compute different digests for the same call. They disagree about what a token
authorizes while passing every delegation case, and the disagreement shows up later as a
signature mismatch a long way from its cause.

The cases look mundane, which is the point: key ordering, `café`, control-character
escapes, `1.0` rendering as `1`, the boundary where `1e20` prints in full and `1e21` does
not, negative zero, empty containers. Each is somewhere two reasonable implementations
diverge without either looking wrong.

[SPEC.md](SPEC.md) documents the file and states what agreement here does *not*
establish - notably that agreeing on canonical output is not agreeing on *which* fields
get canonicalized, which is part of the binding construction and outside these vectors.

## The adapter seam

The harness drives an implementation through the methods in
[`runner/adapter.py`](runner/adapter.py); it owns case selection, decoding, comparison
and reporting. Nothing an adapter does can change which cases run or what counts as a
pass, so two adapters that both report 28/28 are measured identically.

```python
class Adapter:
    def verify_credential(self, credential_json, anchor_did): ...
    def verify_token(self, token_cbor, credential_json, anchor_did, action, at): ...
    def verify_presentation(self, presentation_cbor, challenge_cbor, anchor_did,
                            action, max_age_secs, at): ...
    def token_chain(self, token_cbor): ...
    def verify_rotated_credential(self, key_history_json, credential_json, root_did): ...
    def verify_approver_key_evidence(self, evidence_json, directory_json,
                                     anchor_did, action): ...
    def verify_through_trust_framework(self, config_json, credential_json,
                                       framework_did): ...
    def revocation_lookup(self, list_json, anchor_did, index): ...
    def canonicalize(self, value): ...          # optional; see below
```

Each returns a plain bool (or, for `token_chain`, depth plus the ordered hop
identifiers). Raising is treated as "reject", so an implementation that signals failure by
exception needs no wrapper.

`canonicalize` is the exception on both counts: it returns a string rather than a
decision, and it is optional. An adapter that omits it is reported as **not having run**
the canonicalization suite - not as failing it - because a suite nobody took should never
be folded into a score.

`at` is the file's `evaluated_at`, and it is not optional. Credentials here are minted a
century out, but delegation tokens are capped at one hour by the autonomy ladder and
cannot be - so the tokens expire an hour after the file is generated, and an adapter that
verifies against the wall clock fails every accept case and passes every reject case for
the wrong reason. Use the `_at` entry points. [SPEC.md](SPEC.md) explains why the second
half of that is the dangerous half.

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

The reference implementation passes **28/28** on the delegation suite and **16/16** on
canonicalization.

CI runs the structural validation of both vector files on every push, and checks that the
runner's declared format constants match the files actually shipped - a runner that
refuses its own vectors is a failure neither file can show on its own.

It does **not** yet run the reference implementation, because that package is not on PyPI
at the time of writing. The job reports itself as not executed rather than skipping
quietly, so a green tick here never reads as "the reference implementation passes." It
probes the index on every run and starts exercising the vectors on its own the moment the
package is installable - no change here is needed.

## Provenance

Both vector files are generated, never hand-edited - `vectors.json` by the reference
implementation's `gen_conformance_vectors` example, `jcs_vectors.json` from the
canonicalization suite the three runtimes already share. Keys are random per run, so
regenerating `vectors.json` rewrites the artifacts - they are golden *inputs*, not a fixed
byte snapshot. The `format` field on each file is the compatibility signal: a runner should
refuse a file whose `format` it does not recognize rather than silently skipping unknown
cases. The two files version independently.

Public cryptographic material only - `did:key` identifiers (which encode public keys;
`did:key` cannot represent a private key), signatures, payload hashes and status lists. No
private key or seed appears in this repository.

## License

Apache-2.0. See [LICENSE](LICENSE).
