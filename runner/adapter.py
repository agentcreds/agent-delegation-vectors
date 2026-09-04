"""The interface an implementation implements to be checked against the vectors.

Eight methods. The harness owns case selection, hex decoding, comparison and reporting, so
two implementations that both pass are comparable - neither got to choose which cases ran
or what counted as a pass.

Return a plain ``bool`` for the seven verification methods. **Raising is treated as
reject**, so an implementation that signals failure by exception needs no wrapper; catch
nothing and let it propagate.

There is no base class to inherit. Duck typing is deliberate: an adapter should be able to
wrap an implementation in any state of maturity, including a subprocess or an HTTP call to
a service in another language.
"""

from typing import NamedTuple, Protocol


class Action(NamedTuple):
    """The action a token or presentation is being asked to authorize."""

    tool: str
    parameters: str


class ChainInfo(NamedTuple):
    """The shape of a decoded delegation chain."""

    depth: int
    """0 = minted and never delegated; 1 = one attenuation hop."""

    agent_dids: "list[str]"
    """Ordered hop identifiers, root first. Order is part of the assertion."""


class Implementation(Protocol):
    """Structural type only - adapters need not import or subclass this."""

    def verify_credential(self, credential_json: str, anchor_did: str) -> bool:
        """Verify a capability credential against its issuer's trust anchor."""
        ...

    def verify_token(
        self,
        token_cbor: bytes,
        credential_json: str,
        anchor_did: str,
        action: Action,
    ) -> bool:
        """Verify `action` against an anchor-rooted delegation token.

        The full relying-party check: the credential verifies under the anchor, the token
        derives from it, the root hop was minted by the credential subject, and `action`
        survives every hop's narrowing. Verifying the chain's internal integrity alone is
        NOT sufficient - it would accept a chain rooted in an anchor you do not trust.
        """
        ...

    def verify_presentation(
        self,
        presentation_cbor: bytes,
        challenge_cbor: bytes,
        anchor_did: str,
        action: Action,
        max_age_secs: int,
    ) -> bool:
        """Verify a presentation (token + credential + proof of possession).

        The proof is over the **leaf** key of the chain. On a multi-hop chain that is the
        last delegate, not the original credential subject.
        """
        ...

    def token_chain(self, token_cbor: bytes) -> ChainInfo:
        """Decode a token and report its chain shape.

        The only method that reports what the implementation EXPOSES rather than what it
        decides. Returning an empty or reordered chain is a real defect even when every
        accept/reject case passes, because audit and policy layers consume it.
        """
        ...

    def verify_rotated_credential(
        self,
        key_history_json: str,
        credential_json: str,
        root_did: str,
    ) -> bool:
        """Verify a credential from an organization that has rotated its anchor key.

        `root_did` is the **root** the relying party pinned, not the issuing key. Under
        rotation the issuer DID is not known in advance - that is the point of pinning a
        root: the organization rotates without every relying party re-provisioning.

        The check is: the signed key history is authentic and current against `root_did`,
        the credential's issuer is a key that history still authorizes, and the credential
        verifies under that issuer's key. A history that is unsealed, expired, rooted
        elsewhere, or that has REPUDIATED the issuing key must not authorize it.

        Repudiation is the case worth implementing carefully. A superseded key stays
        valid - planned rotation does not invalidate what the old key signed - while a
        repudiated one does not. Treating the two alike is wrong in one direction or the
        other, and the vectors carry both.
        """
        ...

    def verify_approver_key_evidence(
        self,
        evidence_json: str,
        directory_json: str,
        anchor_did: str,
        action: Action,
    ) -> bool:
        """Verify execution-time approval evidence signed by an **individual approver**.

        The hybrid R10 model. Anchor-signed approval proves the organization approved;
        this proves *who*, by checking the approver key against an org-anchor-signed
        directory. `anchor_did` is the organization anchor the directory verifies under.

        The directory is the only thing binding a key to a human, and it is also the
        joiner/mover/leaver control - removing an entry withdraws that authority. An
        implementation that verifies the signature without consulting the directory will
        pass the accept case and fail every reject case.
        """
        ...

    def verify_through_trust_framework(
        self,
        config_json: str,
        credential_json: str,
        framework_did: str,
    ) -> bool:
        """Resolve a credential's issuer through a framework-signed trust config (R2).

        `framework_did` is the **framework** anchor, not the credential's issuer - that
        is the point: the relying party has no prior relationship with the issuer and
        learns of it only through the config.

        Accept only if the config verifies under `framework_did` **and is current**, the
        issuer is a member, the member meets the config's minimum trust level, and the
        credential verifies under that member's key. The trust level is easy to read and
        forget to enforce, which silently admits under-verified organizations.
        """
        ...

    def revocation_lookup(self, list_json: str, anchor_did: str, index: int) -> bool:
        """Verify a signed status list against `anchor_did`, then report whether `index`
        reads as revoked. Raise if the list does not verify - an unverified list must not
        answer lookups at all.
        """
        ...
