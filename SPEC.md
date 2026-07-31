# Vector file format

`vectors.json` is a single JSON object. A runner reads `format`, refuses a version it
does not recognise, then walks `cases` in order.

```json
{
  "format": 2,
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
| `kind` | all | Selects the check. Unknown kind → fail, do not skip. |
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
subject — an implementation that reaches for the wrong key passes every single-hop case
and fails `presentation_multihop_accept`.

### `token_chain`

Decode `token_cbor_hex` and report its shape. No accept/reject.

| field | assertion |
| --- | --- |
| `expect_depth` | Delegation depth. `0` = minted, never delegated; `1` = one attenuation hop. |
| `expect_chain_agent_dids` | The ordered hop identifiers, root first. Compare as an ordered sequence. |

This is the only case that checks what an implementation **exposes** rather than what it
decides. Verification agreeing while the chain is not readable is a real failure mode:
audit and policy layers consume the chain, and a binding that returns an empty or
reordered one is wrong in a way accept/reject cannot reveal.

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
also pass in an implementation that never granted `tool:email` in the first place — green
for the wrong reason. Read together, the two cases attribute the rejection to attenuation
and nothing else. Runners should report both; passing the rejection while failing the
control is a meaningless result, not a partial success.

## Relationship to `draft-reece-wimse-cross-org-delegation`

These vectors check that two implementations agree on bytes and decisions. That is
narrower than the draft's requirements, and passing them is not conformance to it.

| draft requirement | touched by | not established |
| --- | --- | --- |
| R1 recursive attenuation | the multi-hop cases | that widening is *structurally* impossible, only that this narrowing was enforced |
| R2 cross-org verification | `credential_*`, `token_*` — an anchor-rooted check with no issuer callback | resolution of an unknown issuer through a trust framework, which these vectors do not carry |
| R4 proof of possession | `presentation_*` | audience binding, request binding and freshness, all excluded by the century-long validity |
| R7 revocation | `revocation_lookup` | bounded staleness — the vectors cannot express "older than a configured bound" |

R3, R5, R6, R8, R9 and R10 are **not** covered. Anyone reporting results against these
vectors should say so rather than let "13/13" imply more than it does.

## Adding a case

Cases are generated, not written. Extend the generator in the AgentCreds SDK, regenerate,
bump `format` if any runner would need to change, and update this document — a case whose
obligation is not written down here is not testable by anyone who did not write it.
