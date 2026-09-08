# Vector file format

**Scope.** This document specifies the vector *container* - the JSON envelope, the fields
each case carries, and what each case asserts. It does **not** specify the wire formats of
the artifacts inside: the CBOR envelopes, the delegation-token block layout and its Datalog
conventions, or the credential schema. You can therefore verify an implementation you
already have against these cases; you cannot write one from this document. See the README
on why these are agreement vectors rather than conformance vectors.

There are **two suites**, versioned independently:

| file | suite | what it establishes |
| --- | --- | --- |
| `vectors.json` | delegation | Authorization decisions agree, case by case. |
| `jcs_vectors.json` | canonicalization | Canonical JSON output agrees, byte for byte. |
| `a2a_vectors.json` | A2A layer | The agent-to-agent header/envelope layer above the cryptography - header names, the principal-header scheme, bound-args encoding, the deny-code registry, and octets parse/semantic-equality verdicts - agrees across runtimes. Deterministic string/JSON contracts only: no keys and no clock, so unlike the delegation suite it never expires. Octets bind *output* is deliberately not asserted (the profile makes serialization holder-chosen); only parse + semantic agreement is a contract. |

The second is not decoration. Actions are bound to *canonicalized* arguments, so two
implementations that canonicalize differently compute different digests for the same call.
They then disagree about what a token authorizes while passing every case in the
delegation suite, and the disagreement surfaces later as a signature mismatch a long way
from its cause. The delegation suite structurally cannot catch this, because both sides
canonicalize with their own code before anything the delegation suite observes.

`vectors.json` is a single JSON object. A runner reads `format`, refuses a version it
does not recognize, then walks `cases` in order.

```json
{
  "format": 3,
  "generator": "agentcreds-core examples/gen_conformance_vectors",
  "note": "...",
  "cases": [ { "name": "...", "kind": "...", "...": "..." } ]
}
```

| field | meaning |
| --- | --- |
| `format` | Integer. Incremented whenever a case gains a required field or a new `kind` appears. **Refuse an unrecognised value.** Skipping unknown cases silently reports success for checks that never ran. |
| `generator` | Provenance string. Informational. |
| `evaluated_at` | Unix seconds. **The instant every case must be judged as of.** Not informational - see below. |
| `cases` | Ordered array. Each has `name` (unique) and `kind`. |

All binary artifacts are lowercase hex, no prefix.

## `evaluated_at` - read this before running anything

**Verify as of `evaluated_at`, never against the wall clock.**

Credentials in this file are minted a century out, so they do not expire. **Delegation
tokens cannot be.** A token's lifetime is capped by the autonomy ladder - one hour at
level 0, down to five minutes at level 3 - and that cap is a security control the vectors
do not get to opt out of. So the tokens in this file expire an hour after it was
generated, and there is no way to generate them otherwise.

A harness that uses the wall clock therefore reports, on any file more than an hour old:

- every **accept** case as a failure, because the token has expired; and
- every **reject** case as a pass, **for the wrong reason** - expiry, not the narrowing,
  wrong anchor or out-of-scope action the case exists to check.

The second half is the dangerous one. The run still produces a score, the score is not
zero, and nothing in the output says the rejections were spurious. This happened: the
harness in this repository called the wall-clock verify and reported 23/28, in which four
of the passes established nothing.

Implementations expose this as a separate entry point - `verify_rooted_at`,
`verifyRootedAt`, `Presentation::verify_at` and equivalents - taking the instant as an
argument. One instant must govern the credential, every hop, the Datalog time check and
any proof-of-possession freshness window; a case judged half against `evaluated_at` and
half against the clock is not a result.

A runner that finds no `evaluated_at` must **refuse to run**, not substitute a guess. The
file's modification time and "now" are both plausible and both wrong.

## Common fields

| field | present on | meaning |
| --- | --- | --- |
| `name` | all | Unique, stable identifier. Report it verbatim. |
| `kind` | all | Selects the check. Unknown kind -> fail, do not skip. |
| `anchor_did` | all | The trust anchor to verify against, as a `did:key`. Verification-only; no private key is implied or provided. |
| `expect` | all but `revocation` | `"accept"` or `"reject"`. |
| `action.tool` / `action.parameters` | token, presentation | The action being authorized. `parameters` may be an empty string. |

`expect` is about the **verifier's decision**, not about whether an exception was raised.
An implementation that signals failure by exception and one that returns a status code
must both map to the same accept/reject.

## Kinds

### `credential`

Verify `credential_json` against `anchor_did`.

Establishes: the credential's signature verifies under the stated issuer anchor, and does
not verify under an unrelated one.

### `token`

Decode `token_cbor_hex`, then verify `action` against it, rooted in `credential_json` and
`anchor_did`.

"Rooted" means the full check a relying party should perform: the credential verifies
under the anchor, the token derives from that credential, the root hop was minted by the
credential subject, and the action is within the scope that survives every hop.

Accepting a case marked `reject` means the chain granted something it should not have.

### `presentation`

Decode `presentation_cbor_hex` and `challenge_cbor_hex`, then verify the presentation for
`action` against `anchor_did` with `max_age_secs`.

A presentation carries the token, its backing credential, and a proof of possession of
the **leaf** key. On a multi-hop chain the leaf is the last delegate, not the original
subject - an implementation that reaches for the wrong key passes every single-hop case
and fails `presentation_multihop_accept`.

### `token_chain`

Decode `token_cbor_hex`, verify it, and report its shape.

| field | assertion |
| --- | --- |
| `expect` | `accept` or `reject`, as for every other kind. |
| `expect_depth` | Delegation depth. `0` = minted, never delegated; `1` = one attenuation hop. |
| `expect_chain_agent_dids` | The ordered hop identifiers, root first. Compare as an ordered sequence. |

This is the only case that checks what an implementation **exposes** rather than what it
decides. Verification agreeing while the chain is not readable is a real failure mode:
audit and policy layers consume the chain, and a binding that returns an empty or
reordered one is wrong in a way accept/reject cannot reveal.

### `key_history`

Verify a credential from an organization that has **rotated** its anchor key. Here
`anchor_did` is the **root** the relying party pinned - not the issuing key.

| field | assertion |
| --- | --- |
| `key_history_json` | The organization's signed key history (the portable artifact). |
| `credential_json` | A credential issued by one of its keys. |

Accept only if all of: the history is authentic **and current** against `anchor_did`; the
credential's issuer is a key that history still authorizes; and the credential verifies
under that issuer's key. Reject if the history is unsealed, expired, rooted elsewhere, or
has **repudiated** the issuing key.

Under rotation a relying party cannot know the issuer DID in advance - that is the point
of pinning a root. An implementation that resolves issuers by exact match will reject
every rotated organization, which is a correctness failure, not a conservative one.

### `approval_key`

Verify execution-time approval evidence signed by an **individual approver**, against an
org-anchor-signed directory. Here `anchor_did` is the **organization** anchor the
directory verifies under.

| field | assertion |
| --- | --- |
| `directory_json` | The anchor-signed approver directory. |
| `evidence_json` | Approval evidence signed by an approver's own key. |
| `action` | The action the approval must authorize. |

Accept only if the directory verifies under `anchor_did` and is current, the evidence is
signed by a key that directory **enrols**, the evidence covers this exact action, and it
has not expired.

Anchor-signed approval proves the *organization* approved; this proves *who*. The
directory is the only thing binding a key to a person, so it is also the joiner/mover/
leaver control - removing an entry withdraws that authority. An implementation that
verifies the signature without consulting the directory passes the accept case and fails
every rejection.

### `trust_config`

Resolve a credential's issuer through a **framework-signed trust config** (R2). Here
`anchor_did` is the **framework** anchor - deliberately *not* the credential's issuer.

| field | assertion |
| --- | --- |
| `config_json` | The framework-signed registry snapshot. |
| `credential_json` | A credential whose issuer may or may not be a member. |

Accept only if the config verifies under `anchor_did` **and is current**, the issuer is a
member, the member meets the config's `minimum_trust_level`, and the credential verifies
under that member's registered key.

This is the case that exercises resolving an issuer you have no prior relationship with -
the thing the other kinds deliberately do not cover, since they hand you the anchor.

### `revocation`

Verify `list_json` against `anchor_did`, then look up two indices.

| field | assertion |
| --- | --- |
| `revoked_index` | Must read as revoked. |
| `clear_index` | Must read as not revoked. |

Both matter. A lookup that always returns "revoked" fails safe but is still broken, and
only the clear index catches it.

## The multi-hop cases

Four cases share one two-hop chain: a parent granting `tool:search` and `tool:email`, and
a child attenuated to `tool:search` alone.

| case | expect | establishes |
| --- | --- | --- |
| `token_multihop_accept` | accept | The attenuated chain decodes and authorizes what it still grants. |
| `token_multihop_parent_allows_before_attenuation` | accept | **Control.** The parent hop does allow `tool:email`. |
| `token_multihop_reject_attenuated_away` | reject | The child's narrowing is enforced. |
| `presentation_multihop_accept` | accept | Proof of possession by the leaf key on an attenuated chain. |

The control is not redundant. Without it, `token_multihop_reject_attenuated_away` would
also pass in an implementation that never granted `tool:email` in the first place - green
for the wrong reason. Read together, the two cases attribute the rejection to attenuation
and nothing else. Runners should report both; passing the rejection while failing the
control is a meaningless result, not a partial success.

## The rotation cases

Seven cases share one rotated organization: a root key, a successor, and a history sealed
by the successor.

| case | expect | establishes |
| --- | --- | --- |
| `key_history_accept_rotated_issuer` | accept | The post-rotation key resolves against the pinned root. |
| `key_history_accept_superseded_issuer` | accept | **Control.** A superseded key is still valid under *planned* rotation. |
| `key_history_reject_repudiated_issuer` | reject | The same key, once **repudiated**, is not. |
| `key_history_accept_current_after_repudiation` | accept | **Control.** Repudiating one key does not disable the organization. |
| `key_history_reject_foreign_issuer` | reject | A valid chain is not membership. |
| `key_history_reject_unsealed_history` | reject | An unsigned chain is refused even with intact linkage. |
| `key_history_reject_wrong_root` | reject | The chain must start at the DID that was pinned. |

The two controls carry the weight. `key_history_accept_superseded_issuer` and
`key_history_reject_repudiated_issuer` use the **same credential and the same root**,
differing only in whether the history repudiates that key - so the rejection is
attributable to the repudiation and not to the key merely being old. Without that control,
an implementation that rejects every superseded key would look correct while breaking
planned rotation. Without `key_history_accept_current_after_repudiation`, one that refuses
every issuer the moment any repudiation appears would look correct while disabling the
organization outright.

Two failure directions, two controls. Report them alongside the rejections; a rejection
passing while its control fails is a meaningless result, not a partial success.

Repudiation is deliberately **wholesale** rather than time-bounded. Whoever holds a key
also chooses the issuance timestamp, so "distrust anything issued after T" is forgeable by
backdating. Implementations should not add a cutoff of their own.

## The approver and framework cases

| case | expect | establishes |
| --- | --- | --- |
| `approval_key_accept_enrolled_approver` | accept | An enrolled approver authorizes the action. |
| `approval_key_reject_unenrolled_approver` | reject | **The control.** Same evidence shape, valid signature, key not in the directory. |
| `approval_key_reject_different_action` | reject | Approval is bound to the request, not just the tool. |
| `approval_key_reject_wrong_anchor` | reject | A directory verified under the wrong anchor authorizes nobody. |
| `trust_config_accept_member` | accept | A member resolves through the framework. |
| `trust_config_reject_below_minimum_level` | reject | **The control.** Membership alone is not enough. |
| `trust_config_reject_non_member` | reject | A valid credential from outside the framework. |
| `trust_config_reject_wrong_framework` | reject | The config must verify under the framework anchor. |

Two mistakes these are shaped to catch, both of which pass every accept case:

- **Verifying the approver signature without consulting the directory.** The signature is
  genuine; the question is whether that key is enrolled. Skipping the directory fails
  `reject_unenrolled_approver`, `reject_different_action` and `reject_wrong_anchor` at once.
- **Reading membership but not the trust level.** Easy to do, and it silently admits
  under-verified organizations. Only `reject_below_minimum_level` catches it.

## Relationship to `draft-reece-wimse-cross-org-delegation`

These vectors check that two implementations agree on bytes and decisions. That is
narrower than the draft's requirements, and passing them is not conformance to it.

| draft requirement | touched by | not established |
| --- | --- | --- |
| R1 recursive attenuation | the multi-hop cases | that widening is *structurally* impossible, only that this narrowing was enforced |
| R2 cross-org verification | `credential_*`, `token_*` (anchor-rooted, no issuer callback) and `trust_config_*` (resolution through a framework-signed registry, including the minimum-trust-level gate) | revocation of framework membership, and distribution/freshness of the config itself - the vectors carry no fetch and no staleness bound |
| - key rotation (not an R-numbered requirement) | `key_history_*` - a pinned root followed forward through a signed history | distribution and freshness of the history itself: the vectors carry no fetch, no staleness bound, and no revocation of the history |
| R4 proof of possession | `presentation_*` | audience binding, request binding and freshness, all excluded by the century-long validity |
| R7 revocation | `revocation_lookup` | bounded staleness - the vectors cannot express "older than a configured bound" |

| R10 execution-time authorization | `approval_key_*` - per-approver evidence checked against a signed directory | the *gate* mechanics (which tokens designate approval), one-time reliance, and the approval workflow itself |

R3, R5, R6, R8 and R9 are **not** covered. Anyone reporting results against these
vectors should say so rather than let "28/28" imply more than it does.

## The canonicalization suite - `jcs_vectors.json`

A separate file with its own `format`, currently **1**.

```json
{
  "format": 1,
  "profile": "agentcreds-jcs-v1",
  "spec": "RFC 8785 (JSON Canonicalization Scheme)",
  "note": "...",
  "cases": [ { "value": {"q": "café"}, "expected_jcs": "{\"q\":\"café\"}" } ]
}
```

| field | meaning |
| --- | --- |
| `format` | Integer, versioned independently of `vectors.json`. Refuse an unrecognised value. |
| `profile` | The canonicalization profile these outputs belong to. |
| `spec` | The specification the profile follows. |
| `cases` | Ordered array. Each has `value` and `expected_jcs`. |

### The obligation

For each case: canonicalize `value` and emit **exactly** `expected_jcs`. String equality,
not JSON equivalence - the whole point is the byte sequence, so a result that parses to
the same document but orders keys differently, escapes differently, or renders a number
differently is a failure.

Cases are ordinary-looking on purpose. The suite covers key ordering, non-ASCII
(`café`, `naïve résumé`), control-character escaping, the integer/float boundary
(`1.0` → `1`), the point where large numbers switch to exponent form (`1e20` renders in
full, `1e21` does not), negative zero, and empty containers. Each is a place two
reasonable implementations diverge without either being obviously wrong.

### What it does not establish

Agreement on canonical output is **not** agreement on what gets canonicalized. Which
fields of an action are included, and in what structure, is part of the binding
construction and is outside these vectors entirely. Two implementations can pass every
case here and still disagree about a call, if they disagree about which arguments the
digest covers.

### Not implementing it

The suite is optional for an adapter, and a runner must report an adapter that omits it as
**not having run** rather than folding a zero into a score. An untaken suite reported as a
pass is the failure mode this repository exists to avoid.

## Adding a case

Cases are generated, not written. Extend the generator in the reference implementation,
regenerate, bump `format` if any runner would need to change, and update this document -
a case whose obligation is not written down here is not testable by anyone who did not
write it.

The two suites version independently, and a runner declares which formats it accepts for
each. CI checks those declarations against the shipped files: a runner that refuses its own
vectors is a failure the vector file alone cannot show, and it has happened before.
