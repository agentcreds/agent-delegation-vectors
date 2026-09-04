"""Worked example: the AgentCreds SDK behind the conformance adapter interface.

    pip install agentcreds
    python runner/run_vectors.py --adapter runner/adapters/agentcreds_adapter.py

Kept deliberately thin. Every method is a direct call into the SDK with no fixing-up, no
retries and no special-casing per vector - if an adapter needs any of that, the
implementation it wraps does not agree with the vectors and the run should say so.

Use this as the shape to copy, not as a base class.
"""

import sys
import time
from pathlib import Path

import agentcreds as ac

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adapter import ChainInfo  # noqa: E402


class Adapter:
    """The SDK's verify methods raise on failure, which the harness reads as reject, so
    nothing here catches exceptions."""

    def verify_credential(self, credential_json: str, anchor_did: str) -> bool:
        anchor = ac.TrustAnchor.from_did_key(anchor_did)
        ac.CapabilityCredential.from_json(credential_json).verify(anchor)
        return True

    def verify_token(self, token_cbor, credential_json, anchor_did, action) -> bool:
        anchor = ac.TrustAnchor.from_did_key(anchor_did)
        vc = ac.CapabilityCredential.from_json(credential_json)
        token = ac.DelegationToken.from_cbor(token_cbor)
        # verify_rooted, not verify: the latter proves chain integrity but NOT that the
        # root authority came from an anchor you trust.
        token.verify_rooted(ac.Action(action.tool, action.parameters), vc, anchor)
        return True

    def verify_presentation(
        self, presentation_cbor, challenge_cbor, anchor_did, action, max_age_secs
    ) -> bool:
        anchor = ac.TrustAnchor.from_did_key(anchor_did)
        pres = ac.Presentation.from_cbor(presentation_cbor)
        challenge = ac.PopChallenge.from_cbor(challenge_cbor)
        pres.verify(ac.Action(action.tool, action.parameters), anchor, challenge, max_age_secs)
        return True

    def token_chain(self, token_cbor) -> ChainInfo:
        token = ac.DelegationToken.from_cbor(token_cbor)
        return ChainInfo(
            depth=token.depth(),
            agent_dids=[e.agent_did for e in token.chain().entries],
        )

    def verify_rotated_credential(
        self, key_history_json: str, credential_json: str, root_did: str
    ) -> bool:
        # authorize_issuer does the whole relying-party check in one call: it verifies the
        # sealed chain against the pinned root, enforces freshness, refuses a repudiated
        # key, and returns the anchor to verify the credential with.
        history = ac.KeyHistory.from_json(key_history_json)
        vc = ac.CapabilityCredential.from_json(credential_json)
        vc.verify(history.authorize_issuer(root_did, vc.issuer))
        return True

    def verify_approver_key_evidence(
        self, evidence_json: str, directory_json: str, anchor_did: str, action
    ) -> bool:
        anchor = ac.TrustAnchor.from_did_key(anchor_did)
        directory = ac.ApproverDirectory.from_json(directory_json)
        evidence = ac.ApprovalEvidence.from_json(evidence_json)
        evidence.verify_with_directory(
            ac.Action(action.tool, action.parameters), directory, anchor, int(time.time())
        )
        return True

    def verify_through_trust_framework(
        self, config_json: str, credential_json: str, framework_did: str
    ) -> bool:
        framework = ac.TrustAnchor.from_did_key(framework_did)
        config = ac.SignedTrustConfig.from_json(config_json)
        config.verify_current(framework)  # authenticity AND freshness
        registry = ac.TrustRegistry.from_config(config, framework)
        vc = ac.CapabilityCredential.from_json(credential_json)
        entry = registry.verify_credential(vc)  # membership + minimum trust level
        vc.verify(ac.TrustAnchor.from_did_key(entry.did))
        return True

    def revocation_lookup(self, list_json: str, anchor_did: str, index: int) -> bool:
        anchor = ac.TrustAnchor.from_did_key(anchor_did)
        lst = ac.RevocationList.from_json(list_json)
        lst.verify(anchor)  # raises if not authentic - an unverified list answers nothing
        return lst.is_revoked(index)
