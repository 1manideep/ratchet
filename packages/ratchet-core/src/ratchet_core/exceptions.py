"""ratchet_core.exceptions — exception hierarchy for the Ratchet broker.

Broker.authorize() never raises one of these for an ordinary policy denial —
it always returns an explicit Decision (see broker.py) so adapters can build
clean, framework-native rejection messages and audit entries. These
exceptions are raised by the *constructive* token APIs (mint, attenuate,
exchange, deserialize) where raising is the right shape, and are also
available to adapters that prefer to re-raise a Decision as an exception in
their own framework's idiom.
"""

from __future__ import annotations


class RatchetError(Exception):
    """Base class for all Ratchet errors."""


class RatchetDenied(RatchetError):
    """A policy or verification check failed. Carries a stable `reason_code`."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        message = f"RatchetDenied({reason_code})" + (f": {detail}" if detail else "")
        super().__init__(message)


class RatchetExpired(RatchetDenied):
    """A token has passed its (most restrictive) expires_at caveat."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(reason_code="EXPIRED", detail=detail)


class RatchetRevoked(RatchetDenied):
    """A token, or an ancestor in its delegation chain, has been revoked."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(reason_code="REVOKED", detail=detail)


class RatchetInvalidSignature(RatchetDenied):
    """A token's HMAC signature chain does not verify against the broker secret."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(reason_code="INVALID_SIGNATURE", detail=detail)


class RatchetNotBound(RatchetDenied):
    """The presenting identity does not match the token's bound_to fingerprint."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(reason_code="NOT_BOUND", detail=detail)


class RatchetMalformedToken(RatchetDenied):
    """A token or caveat could not be parsed, or has an invalid internal shape."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(reason_code="MALFORMED", detail=detail)


class RatchetNotNarrowing(RatchetError):
    """Raised by attenuate()/exchange() when new caveats do not strictly narrow the parent."""

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        super().__init__(f"RatchetNotNarrowing: {detail}" if detail else "RatchetNotNarrowing")


class RatchetDepthExceeded(RatchetDenied):
    """A token's max_depth caveat would be violated by minting another delegation hop."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(reason_code="DEPTH_EXCEEDED", detail=detail)
