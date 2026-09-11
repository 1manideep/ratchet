"""ratchet_core.tokens — macaroon-style capability tokens.

A Token is `{root_id, chain, caveats_by_hop, signature}`. Signature
chaining follows the paper's construction (Section 7.2): starting from
`sig_0 = HMAC(secret, root_id)`, each hop folds in its own token_id and then
each caveat added at that hop, in order:

    sig = HMAC(sig, "hop:" + token_id)
    for caveat in hop_caveats:
        sig = HMAC(sig, canonical_json(caveat))

Because every hop's token_id is itself folded into the chain, an attacker
cannot relabel a token's id/lineage without invalidating the signature —
this is what lets Broker.authorize() do per-hop revocation checks safely
(see revocation.py). Because caveats are only ever appended, stripping or
widening a caveat also breaks the signature. Forging any of this requires
the broker secret.

Two ways to grow a token, both here for a single reason — only one of them
may touch `bound_to`:

  - `attenuate()`   — public, general-purpose narrowing. Refuses to touch
                       BOUND_TO at all.
  - `rebind_for_exchange()` — broker-privileged. Only Broker.exchange()
                       calls this, and only after verifying the presenting
                       identity holds the parent token's current bound_to.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass

from ratchet_core.caveats import (
    Caveat,
    CaveatKind,
    bound_to_caveat,
    check_narrowing,
    expires_at_caveat,
    extract_expires_at,
)
from ratchet_core.exceptions import RatchetMalformedToken, RatchetNotNarrowing

_TOKEN_ID_BYTES = 16


@dataclass(frozen=True, slots=True)
class Token:
    """An immutable capability token. Construct only via mint_root/attenuate/rebind_for_exchange."""

    root_id: str
    chain: tuple[str, ...]
    caveats_by_hop: tuple[tuple[Caveat, ...], ...]
    signature: str

    @property
    def token_id(self) -> str:
        """This token's own id — the most recent hop in `chain`."""
        return self.chain[-1]

    @property
    def caveats(self) -> tuple[Caveat, ...]:
        """All caveats across all hops, root to self, in append order."""
        return tuple(c for hop in self.caveats_by_hop for c in hop)

    @property
    def depth(self) -> int:
        """Delegation depth: 0 for the root token, +1 per exchange() hop."""
        return len(self.chain) - 1


def token_identity_chain(token: Token) -> tuple[str, ...]:
    """Fingerprints of each hop's holder, in order — only hops that rebound the
    token (mint_root, rebind_for_exchange) contribute; attenuate() never does."""
    chain: list[str] = []
    for hop_caveats in token.caveats_by_hop:
        for caveat in hop_caveats:
            if caveat.kind is CaveatKind.BOUND_TO:
                fingerprint = caveat.params.get("fingerprint")
                if isinstance(fingerprint, str):
                    chain.append(fingerprint)
    return tuple(chain)


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _compute_signature(
    secret: bytes,
    root_id: str,
    chain: Sequence[str],
    caveats_by_hop: Sequence[Sequence[Caveat]],
) -> str:
    sig = hmac.new(secret, root_id.encode("utf-8"), hashlib.sha256).digest()
    for token_id, hop_caveats in zip(chain, caveats_by_hop, strict=True):
        sig = hmac.new(sig, f"hop:{token_id}".encode(), hashlib.sha256).digest()
        for caveat in hop_caveats:
            payload = _canonical_json(caveat.to_canonical_dict()).encode("utf-8")
            sig = hmac.new(sig, payload, hashlib.sha256).digest()
    return sig.hex()


def verify_signature(token: Token, secret: bytes) -> bool:
    """Recompute the signature chain from scratch and compare in constant time."""
    if len(token.chain) != len(token.caveats_by_hop):
        return False
    expected = _compute_signature(secret, token.root_id, token.chain, token.caveats_by_hop)
    return hmac.compare_digest(expected, token.signature)


def mint_root(
    *,
    secret: bytes,
    root_id: str,
    bound_to_fingerprint: str,
    caveats: Sequence[Caveat],
    ttl_seconds: float,
) -> Token:
    """Mint the root capability token (cap1), bound to the primary agent's identity."""
    token_id = secrets.token_hex(_TOKEN_ID_BYTES)
    hop_caveats = (
        bound_to_caveat(bound_to_fingerprint),
        expires_at_caveat(time.time() + ttl_seconds),
        *caveats,
    )
    chain = (token_id,)
    caveats_by_hop = (hop_caveats,)
    signature = _compute_signature(secret, root_id, chain, caveats_by_hop)
    return Token(root_id=root_id, chain=chain, caveats_by_hop=caveats_by_hop, signature=signature)


def attenuate(token: Token, *, secret: bytes, new_caveats: Sequence[Caveat]) -> Token:
    """Narrow `token` by appending `new_caveats` at a new hop. Never rebinds the holder.

    Raises RatchetNotNarrowing if any new caveat could widen authority, or
    attempts to set bound_to (use Broker.exchange() to delegate instead).
    """
    if any(c.kind is CaveatKind.BOUND_TO for c in new_caveats):
        raise RatchetNotNarrowing("bound_to may only be set via Broker.exchange(), not attenuate()")
    check_narrowing(token.caveats, new_caveats)

    new_token_id = secrets.token_hex(_TOKEN_ID_BYTES)
    chain = (*token.chain, new_token_id)
    caveats_by_hop = (*token.caveats_by_hop, tuple(new_caveats))
    signature = _compute_signature(secret, token.root_id, chain, caveats_by_hop)
    return Token(
        root_id=token.root_id, chain=chain, caveats_by_hop=caveats_by_hop, signature=signature
    )


def rebind_for_exchange(
    token: Token,
    *,
    secret: bytes,
    new_bound_to_fingerprint: str,
    extra_caveats: Sequence[Caveat],
    ttl_seconds: float,
) -> Token:
    """Mint a child token bound to a new workload identity.

    Broker-privileged: call only from Broker.exchange(), after verifying the
    presenting identity holds `token`'s current bound_to caveat. Do not call
    this directly from adapters or application code.
    """
    if any(c.kind is CaveatKind.BOUND_TO for c in extra_caveats):
        raise RatchetNotNarrowing(
            "extra_caveats must not include bound_to; it is set automatically"
        )

    parent_expiry = extract_expires_at(token.caveats)
    requested_expiry = time.time() + ttl_seconds
    new_expiry = (
        min(parent_expiry, requested_expiry) if parent_expiry is not None else requested_expiry
    )

    non_bound_new_caveats = (expires_at_caveat(new_expiry), *extra_caveats)
    check_narrowing(token.caveats, non_bound_new_caveats)

    hop_caveats = (bound_to_caveat(new_bound_to_fingerprint), *non_bound_new_caveats)
    new_token_id = secrets.token_hex(_TOKEN_ID_BYTES)
    chain = (*token.chain, new_token_id)
    caveats_by_hop = (*token.caveats_by_hop, hop_caveats)
    signature = _compute_signature(secret, token.root_id, chain, caveats_by_hop)
    return Token(
        root_id=token.root_id, chain=chain, caveats_by_hop=caveats_by_hop, signature=signature
    )


def serialize_token(token: Token) -> str:
    """Serialize `token` to a compact base64url string suitable as a bearer token."""
    payload = {
        "root_id": token.root_id,
        "chain": list(token.chain),
        "caveats_by_hop": [[c.to_canonical_dict() for c in hop] for hop in token.caveats_by_hop],
        "signature": token.signature,
    }
    raw = _canonical_json(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def deserialize_token(data: str) -> Token:
    """Parse a token produced by serialize_token(). Fails closed (RatchetMalformedToken) on any error.

    Rejects non-canonical base64url encodings: base64 has "don't-care" bits
    at quantum boundaries, so a mutated string can decode to the exact same
    bytes as a valid token without being identical to it. Re-encoding and
    requiring an exact match closes that off, rather than treating one
    logical token as if it had two valid string forms.
    """
    try:
        padded = data + "=" * (-len(data) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != data:
            raise RatchetMalformedToken("non-canonical token encoding")
        payload = json.loads(raw)
        chain = tuple(payload["chain"])
        caveats_by_hop = tuple(
            tuple(Caveat.from_dict(c) for c in hop) for hop in payload["caveats_by_hop"]
        )
        return Token(
            root_id=payload["root_id"],
            chain=chain,
            caveats_by_hop=caveats_by_hop,
            signature=payload["signature"],
        )
    except RatchetMalformedToken:
        raise
    except (KeyError, ValueError, TypeError, UnicodeDecodeError, binascii.Error) as exc:
        raise RatchetMalformedToken(f"could not deserialize token: {exc}") from exc
