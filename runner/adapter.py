"""The interface an implementation implements to be checked against the vectors.

Five methods. The harness owns case selection, hex decoding, comparison and reporting, so
two implementations that both pass are comparable — neither got to choose which cases ran
or what counted as a pass.

Return a plain ``bool`` for the four verification methods. **Raising is treated as
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

    def revocation_lookup(self, list_json: str, anchor_did: str, index: int) -> bool:
        """Verify a signed status list against `anchor_did`, then report whether `index`
        reads as revoked. Raise if the list does not verify - an unverified list must not
        answer lookups at all.
        """
        ...
