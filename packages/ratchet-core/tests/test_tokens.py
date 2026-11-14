"""Unit tests for ratchet_core.tokens: minting, attenuation, rebinding, (de)serialization."""

from __future__ import annotations

import base64
import dataclasses
import json
import re

import pytest

from ratchet_core import (
    Caveat,
    CaveatKind,
    RatchetMalformedToken,
    RatchetNotNarrowing,
    arg_constraint_caveat,
    attenuate,
    bound_to_caveat,
    deserialize_token,
    expires_at_caveat,
    extract_bound_to,
    extract_expires_at,
    extract_max_depth,
    max_depth_caveat,
    mint_root,
    rebind_for_exchange,
    serialize_token,
    tool_name_caveat,
    verify_signature,
)

from .conftest import TEST_SECRET


def test_mint_root_binds_to_primary_and_verifies(primary_identity):
    token = mint_root(
        secret=TEST_SECRET,
        root_id="human:alice:abc123",
        bound_to_fingerprint=primary_identity.fingerprint,
        caveats=[tool_name_caveat("send_email")],
        ttl_seconds=900,
    )
    assert token.depth == 0
    assert extract_bound_to(token.caveats) == primary_identity.fingerprint
    assert verify_signature(token, TEST_SECRET)


def test_verify_signature_fails_with_wrong_secret(root_token):
    assert not verify_signature(root_token, b"not-the-real-secret")


def test_attenuate_narrows_tool_name_with_and_semantics(root_token):
    narrowed = attenuate(
        root_token, secret=TEST_SECRET, new_caveats=[tool_name_caveat("read_calendar")]
    )
    assert verify_signature(narrowed, TEST_SECRET)
    tool_name_caveats = [c for c in narrowed.caveats if c.kind is CaveatKind.TOOL_NAME]
    assert len(tool_name_caveats) == 2  # original + narrower addition, ANDed at authorize time


def test_attenuate_rejects_bound_to(root_token, attacker_identity):
    with pytest.raises(RatchetNotNarrowing):
        attenuate(
            root_token,
            secret=TEST_SECRET,
            new_caveats=[bound_to_caveat(attacker_identity.fingerprint)],
        )


def test_attenuate_accepts_narrower_max_depth(root_token):
    narrowed = attenuate(root_token, secret=TEST_SECRET, new_caveats=[max_depth_caveat(2)])
    assert extract_max_depth(narrowed.caveats) == 2


def test_attenuate_rejects_wider_max_depth(root_token):
    with pytest.raises(RatchetNotNarrowing):
        attenuate(root_token, secret=TEST_SECRET, new_caveats=[max_depth_caveat(50)])


def test_attenuate_rejects_equal_max_depth_as_noop(root_token):
    existing = extract_max_depth(root_token.caveats)
    with pytest.raises(RatchetNotNarrowing):
        attenuate(root_token, secret=TEST_SECRET, new_caveats=[max_depth_caveat(existing)])


def test_attenuate_accepts_earlier_expires_at(root_token):
    earlier = extract_expires_at(root_token.caveats) - 100
    narrowed = attenuate(root_token, secret=TEST_SECRET, new_caveats=[expires_at_caveat(earlier)])
    assert extract_expires_at(narrowed.caveats) == earlier


def test_attenuate_rejects_later_expires_at(root_token):
    later = extract_expires_at(root_token.caveats) + 100
    with pytest.raises(RatchetNotNarrowing):
        attenuate(root_token, secret=TEST_SECRET, new_caveats=[expires_at_caveat(later)])


def test_tampering_a_caveat_breaks_signature(root_token):
    tampered_hop = tuple(
        Caveat(kind=CaveatKind.TOOL_NAME, params={"pattern": ".*"})
        if c.kind is CaveatKind.TOOL_NAME
        else c
        for c in root_token.caveats_by_hop[0]
    )
    tampered = dataclasses.replace(root_token, caveats_by_hop=(tampered_hop,))
    assert not verify_signature(tampered, TEST_SECRET)


def test_stripping_a_caveat_breaks_signature(root_token):
    stripped_hop = root_token.caveats_by_hop[0][:-1]
    stripped = dataclasses.replace(root_token, caveats_by_hop=(stripped_hop,))
    assert not verify_signature(stripped, TEST_SECRET)


def test_rebind_for_exchange_changes_holder(root_token, sub_identity):
    child = rebind_for_exchange(
        root_token,
        secret=TEST_SECRET,
        new_bound_to_fingerprint=sub_identity.fingerprint,
        extra_caveats=[tool_name_caveat("read_calendar")],
        ttl_seconds=300,
    )
    assert extract_bound_to(child.caveats) == sub_identity.fingerprint
    assert child.depth == root_token.depth + 1
    assert verify_signature(child, TEST_SECRET)


def test_rebind_for_exchange_rejects_bound_to_in_extra_caveats(
    root_token, sub_identity, attacker_identity
):
    with pytest.raises(RatchetNotNarrowing):
        rebind_for_exchange(
            root_token,
            secret=TEST_SECRET,
            new_bound_to_fingerprint=sub_identity.fingerprint,
            extra_caveats=[bound_to_caveat(attacker_identity.fingerprint)],
            ttl_seconds=300,
        )


def test_rebind_for_exchange_clamps_ttl_to_parent_expiry(root_token, sub_identity):
    child = rebind_for_exchange(
        root_token,
        secret=TEST_SECRET,
        new_bound_to_fingerprint=sub_identity.fingerprint,
        extra_caveats=[],
        ttl_seconds=10_000,  # far longer than the parent's remaining lifetime
    )
    assert extract_expires_at(child.caveats) <= extract_expires_at(root_token.caveats)


def test_serialize_deserialize_round_trip(root_token):
    blob = serialize_token(root_token)
    restored = deserialize_token(blob)
    assert restored == root_token
    assert verify_signature(restored, TEST_SECRET)


def _payload_text(blob: str) -> str:
    return base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")


def _as_token_string(payload_text: str) -> str:
    """A payload in canonical base64url, so only the JSON inside differs from a real token."""
    return base64.urlsafe_b64encode(payload_text.encode("utf-8")).decode("ascii").rstrip("=")


def test_deserialize_rejects_other_spellings_of_a_valid_token(root_token):
    """One token, one string. JSON can spell the same token several ways (a float written with a trailing zero
    or a different last digit that rounds to the same value, spacing, key order), all decoding to an equal,
    validly signed Token: only the string serialize_token() writes is accepted. The fuzz test found one such
    spelling about once in 200,000 mutations."""
    blob = serialize_token(root_token)
    text = _payload_text(blob)
    stamp = re.search(r'"timestamp":([0-9.]+)', text)
    assert stamp is not None
    variants = [
        text.replace(stamp.group(0), stamp.group(0) + "0", 1),  # the same float, written longer
        text.replace(",", ", ", 1),
        json.dumps(dict(reversed(list(json.loads(text).items()))), separators=(",", ":")),
    ]
    for variant in variants:
        assert variant != text
        assert json.loads(variant) == json.loads(text)  # the same token, spelled differently
        with pytest.raises(RatchetMalformedToken):
            deserialize_token(_as_token_string(variant))


def test_deserialize_garbage_fails_closed():
    with pytest.raises(RatchetMalformedToken):
        deserialize_token("not-a-valid-token-at-all")


def test_deserialize_truncated_valid_token_fails_closed(root_token):
    blob = serialize_token(root_token)
    with pytest.raises(RatchetMalformedToken):
        deserialize_token(blob[: len(blob) // 2])


def test_arg_constraint_caveat_pattern_mode():
    caveat = arg_constraint_caveat("email", pattern=r".+@example\.com")
    assert caveat.params["key"] == "email"
    assert "pattern" in caveat.params
    assert "equals" not in caveat.params
