"""ratchet_core.identity — workload identity (SVID-equivalent) for agents.

Each agent (primary or sub-agent) gets an Ed25519 keypair generated at
startup; its public-key fingerprint is the SVID-equivalent, addressed as
`ratchet://<agent_id>/<fingerprint>`. No external identity server is
required for v0.1 — identities are self-issued and registered with the
broker's in-memory IdentityRegistry at agent startup.

`WorkloadIdentity` is an abstract interface specifically so a future
`ratchet-spiffe` package can supply real SPIFFE SVIDs without changing the
broker or any framework adapter.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RATCHET_URI_SCHEME = "ratchet"


class WorkloadIdentity(ABC):
    """Cryptographically verifiable workload identity (SVID-equivalent)."""

    @property
    @abstractmethod
    def agent_id(self) -> str:
        """Human-readable identifier for the workload (e.g. "primary-agent")."""

    @property
    @abstractmethod
    def fingerprint(self) -> str:
        """Stable fingerprint of the identity's public key."""

    @property
    def uri(self) -> str:
        """SVID-equivalent URI: ratchet://<agent_id>/<fingerprint>."""
        return f"{RATCHET_URI_SCHEME}://{self.agent_id}/{self.fingerprint}"

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign a message with the workload's private key."""

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against the workload's public key."""

    @abstractmethod
    def as_public(self) -> WorkloadIdentity:
        """Return a copy holding only the public key (safe to register/share)."""


def _fingerprint_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


class Ed25519WorkloadIdentity(WorkloadIdentity):
    """A workload identity holding its own Ed25519 private key."""

    def __init__(self, agent_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self._agent_id = agent_id
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._fingerprint = _fingerprint_for(self._public_key)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def as_public(self) -> WorkloadIdentity:
        return PublicWorkloadIdentity(self._agent_id, self._public_key)


class PublicWorkloadIdentity(WorkloadIdentity):
    """A workload identity known only by its public key — cannot sign."""

    def __init__(self, agent_id: str, public_key: Ed25519PublicKey) -> None:
        self._agent_id = agent_id
        self._public_key = public_key
        self._fingerprint = _fingerprint_for(public_key)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError("PublicWorkloadIdentity holds no private key and cannot sign")

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def as_public(self) -> WorkloadIdentity:
        return self


class IdentityRegistry:
    """In-memory registry of known workload identities, keyed by fingerprint.

    Never stores private keys — `register()` always stores `as_public()`.
    """

    def __init__(self) -> None:
        self._by_fingerprint: dict[str, WorkloadIdentity] = {}

    def register(self, identity: WorkloadIdentity) -> None:
        self._by_fingerprint[identity.fingerprint] = identity.as_public()

    def get(self, fingerprint: str) -> WorkloadIdentity | None:
        return self._by_fingerprint.get(fingerprint)

    def is_registered(self, fingerprint: str) -> bool:
        return fingerprint in self._by_fingerprint
