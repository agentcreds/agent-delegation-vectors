# Vector file format

**Scope.** This document specifies the vector *container* - the JSON envelope, the fields
each case carries, and what each case asserts. It does **not** specify the wire formats of
the artifacts inside: the CBOR envelopes, the delegation-token block layout and its Datalog
conventions, or the credential schema. You can therefore verify an implementation you
already have against these cases; you cannot write one from this document. See the README
on why these are agreement vectors rather than conformance vectors.

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
| `cases` | Ordered array. Each has `name` (unique) and `kind`. |

All binary artifacts are lowercase hex, no prefix. All timestamps inside the artifacts
are set a century out, so the file does not expire and freshness failures are never the
reason a case rejects.

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

## Adding a case

Cases are generated, not written. Extend the generator in the reference implementation,
regenerate, bump `format` if any runner would need to change, and update this document -
a case whose obligation is not written down here is not testable by anyone who did not
write it.
