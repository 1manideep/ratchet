"""Adversarial robustness tests — mirrors Section 7.3 of arXiv:2609.00267.

Two groups:

1. The 11 direct attacks on the broker's own design (attack_01..attack_11),
   each asserting the broker rejects it.
2. The four named threats (T1-T4) as end-to-end scenarios: an "unguarded"
   baseline (bearer token, no broker) succeeds — demonstrating the
   vulnerability — while the Ratchet-guarded path is blocked.
"""

from __future__ import annotations

import dataclasses
import time

import pytest

from ratchet_core import (
    Caveat,
    CaveatKind,
    ProposedToolCall,
    RatchetDepthExceeded,
    RatchetNotBound,
    RatchetNotNarrowing,
    arg_constraint_caveat,
    bound_to_caveat,
    expires_at_caveat,
    max_depth_caveat,
    mint_root,
    tool_name_caveat,
)
from ratchet_core.tokens import Token, attenuate, rebind_for_exchange

from .conftest import TEST_SECRET

# ---------------------------------------------------------------------------
# 1. The 11 direct attacks on the broker's own design
# ---------------------------------------------------------------------------


def test_attack_01_forge_from_scratch(broker, attacker_identity):
    forged = Token(
        root_id="human:eve:forged",
        chain=("fake-token-id",),
        caveats_by_hop=(
            (
                bound_to_caveat(attacker_identity.fingerprint),
                expires_at_caveat(time.time() + 900),
            ),
        ),
        signature="deadbeef" * 8,
    )
    decision = broker.authorize(
        forged,
        presenting_identity=attacker_identity,
        proposed_tool_call=ProposedToolCall(tool_name="send_email", args={}),
    )
    assert not decision.allowed
    assert decision.reason_code == "INVALID_SIGNATURE"


def test_attack_02_forge_with_guessed_secret(broker, attacker_identity):
    guessed_secret = b"a-plausible-but-wrong-guessed-secret"
    forged = mint_root(
        secret=guessed_secret,
        root_id="human:eve:guessed",
        bound_to_fingerprint=attacker_identity.fingerprint,
        caveats=[tool_name_caveat(".*")],
        ttl_seconds=900,
    )
    decision = broker.authorize(
        forged,
        presenting_identity=attacker_identity,
        proposed_tool_call=ProposedToolCall(tool_name="send_email", args={}),
    )
    assert not decision.allowed
    assert decision.reason_code == "INVALID_SIGNATURE"


def test_attack_03_strip_a_caveat(broker, root_token, primary_identity):
    stripped_hop = root_token.caveats_by_hop[0][:-1]
    stripped = dataclasses.replace(root_token, caveats_by_hop=(stripped_hop,))
    decision = broker.authorize(
        stripped,
        presenting_identity=primary_identity,
        proposed_tool_call=ProposedToolCall(tool_name="send_email", args={}),
    )
    assert not decision.allowed
    assert decision.reason_code == "INVALID_SIGNATURE"


def test_attack_04_widen_a_caveat_without_exchange(root_token):
    # Even with the real secret in hand, the attenuate() primitive itself
    # refuses to widen — this is the guardrail that matters when exchange()
    # is bypassed (e.g. a buggy or malicious adapter calling tokens.* directly).
    with pytest.raises(RatchetNotNarrowing):
        attenuate(root_token, secret=TEST_SECRET, new_caveats=[max_depth_caveat(999)])


def test_attack_05_rebind_stolen_token_to_different_svid(root_token, attacker_identity):
    # Editing bound_to without the secret breaks the signature chain.
    tampered_last_hop = tuple(
        bound_to_caveat(attacker_identity.fingerprint) if c.kind is CaveatKind.BOUND_TO else c
        for c in root_token.caveats_by_hop[-1]
    )
    tampered = dataclasses.replace(
        root_token, caveats_by_hop=(*root_token.caveats_by_hop[:-1], tampered_last_hop)
    )
    from ratchet_core import verify_signature

    assert not verify_signature(tampered, TEST_SECRET)


def test_attack_06_replay_valid_token_from_unbound_identity(broker, root_token, attacker_identity):
    decision = broker.authorize(
        root_token,
        presenting_identity=attacker_identity,
        proposed_tool_call=ProposedToolCall(tool_name="send_email", args={}),
    )
    assert not decision.allowed
    assert decision.reason_code == "NOT_BOUND"


def test_attack_07_malformed_caveat_fails_closed(broker, primary_identity):
    malformed = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary_identity,
        caveats=[Caveat(kind=CaveatKind.ARG_CONSTRAINT, params={})],  # missing required 'key'
    )
    decision = broker.authorize(
        malformed,
        presenting_identity=primary_identity,
        proposed_tool_call=ProposedToolCall(tool_name="send_email", args={"to": "x"}),
    )
    assert not decision.allowed  # fail closed, never an implicit ALLOW


def test_attack_08_widen_scope_via_exchange(broker, root_token, primary_identity, sub_identity):
    with pytest.raises(RatchetNotNarrowing):
        broker.exchange(
            parent_token=root_token,
            delegator_identity=primary_identity,
            delegatee_identity=sub_identity,
            new_caveats=[max_depth_caveat(999)],  # root_token's max_depth is 5
        )


def test_attack_09_delegate_a_token_one_does_not_hold(
    broker, root_token, sub_identity, attacker_identity
):
    with pytest.raises(RatchetNotBound):
        broker.exchange(
            parent_token=root_token,
            delegator_identity=attacker_identity,  # root_token is bound to primary, not attacker
            delegatee_identity=sub_identity,
            new_caveats=[tool_name_caveat("read_calendar")],
        )


def test_attack_10_use_a_child_of_a_revoked_token(
    broker, root_token, primary_identity, sub_identity
):
    child = broker.exchange(
        parent_token=root_token,
        delegator_identity=primary_identity,
        delegatee_identity=sub_identity,
        new_caveats=[tool_name_caveat("read_calendar")],
    )
    broker.revocation_store.revoke_root(root_token.root_id)

    decision = broker.authorize(
        child,
        presenting_identity=sub_identity,
        proposed_tool_call=ProposedToolCall(tool_name="read_calendar", args={}),
    )
    assert not decision.allowed
    assert decision.reason_code == "REVOKED"


def test_attack_11_use_an_expired_token(broker, primary_identity):
    expired = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary_identity,
        caveats=[tool_name_caveat(".*")],
        ttl_seconds=-1,  # already expired
    )
    decision = broker.authorize(
        expired,
        presenting_identity=primary_identity,
        proposed_tool_call=ProposedToolCall(tool_name="send_email", args={}),
    )
    assert not decision.allowed
    assert decision.reason_code == "EXPIRED"


def test_attack_08b_widen_max_depth_via_rebind_for_exchange_directly(root_token, sub_identity):
    # Same guardrail, exercised at the tokens.py layer rather than Broker.exchange().
    with pytest.raises(RatchetNotNarrowing):
        rebind_for_exchange(
            root_token,
            secret=TEST_SECRET,
            new_bound_to_fingerprint=sub_identity.fingerprint,
            extra_caveats=[max_depth_caveat(999)],
            ttl_seconds=300,
        )


def test_exchange_respects_max_depth_exceeded(broker, primary_identity, sub_identity):
    shallow_root = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary_identity,
        caveats=[tool_name_caveat(".*"), max_depth_caveat(0)],
    )
    with pytest.raises(RatchetDepthExceeded):
        broker.exchange(
            parent_token=shallow_root,
            delegator_identity=primary_identity,
            delegatee_identity=sub_identity,
            new_caveats=[tool_name_caveat("read_calendar")],
        )


# ---------------------------------------------------------------------------
# 2. T1-T4: default/unguarded runtime fails, Ratchet-guarded blocks
# ---------------------------------------------------------------------------


class _UnguardedBearerRuntime:
    """Models "common framework practice" per the paper: a single broad bearer
    token is handed to sub-agents unchanged, and nothing mediates tool calls."""

    def call_tool(self, bearer_token: str, tool_name: str, args: dict) -> bool:
        return True  # no authorization check of any kind — always succeeds


def test_t1_confused_deputy_unguarded_baseline_succeeds():
    runtime = _UnguardedBearerRuntime()
    # Injected content redirects a legitimate "send_email" action to an
    # attacker-controlled recipient outside the intended domain constraint.
    assert runtime.call_tool("bearer-token", "send_email", {"to": "eve@attacker.example"}) is True


def test_t1_confused_deputy_blocked_by_ratchet(broker, primary_identity):
    token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary_identity,
        caveats=[
            tool_name_caveat("send_email"),
            arg_constraint_caveat("to", pattern=r".+@example\.com"),
        ],
    )
    decision = broker.authorize(
        token,
        presenting_identity=primary_identity,
        proposed_tool_call=ProposedToolCall(
            tool_name="send_email", args={"to": "eve@attacker.example"}
        ),
    )
    assert not decision.allowed
    assert decision.reason_code == "CAVEAT_NOT_SATISFIED"


def test_t2_token_theft_replay_unguarded_baseline_succeeds():
    runtime = _UnguardedBearerRuntime()
    stolen_bearer_token = "bearer-token-exfiltrated-from-compromised-tool"
    assert runtime.call_tool(stolen_bearer_token, "refund_payment", {"amount": 10_000}) is True


def test_t2_token_theft_replay_blocked_by_ratchet(broker, root_token, attacker_identity):
    decision = broker.authorize(
        root_token,
        presenting_identity=attacker_identity,  # attacker replaying a stolen token
        proposed_tool_call=ProposedToolCall(tool_name="refund_payment", args={"amount": 10_000}),
    )
    assert not decision.allowed
    assert decision.reason_code == "NOT_BOUND"


def test_t3_privilege_escalation_unguarded_baseline_succeeds():
    runtime = _UnguardedBearerRuntime()
    # Agent was only ever supposed to read calendars; injected content
    # escalates it into sending email using the same bearer token.
    assert runtime.call_tool("bearer-token", "send_email", {"to": "anyone@example.com"}) is True


def test_t3_privilege_escalation_blocked_by_ratchet(broker, primary_identity):
    read_only_token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary_identity,
        caveats=[tool_name_caveat("read_calendar")],
    )
    decision = broker.authorize(
        read_only_token,
        presenting_identity=primary_identity,
        proposed_tool_call=ProposedToolCall(
            tool_name="send_email", args={"to": "anyone@example.com"}
        ),
    )
    assert not decision.allowed
    assert decision.reason_code == "CAVEAT_NOT_SATISFIED"


def test_t4_compromised_sub_agent_unguarded_baseline_succeeds():
    runtime = _UnguardedBearerRuntime()
    # Naive bearer delegation: sub-agent inherits the primary's full token,
    # unattenuated, so a compromised sub-agent can call anything the primary could.
    assert (
        runtime.call_tool("primarys-full-bearer-token", "refund_payment", {"amount": 999_999})
        is True
    )


def test_t4_compromised_sub_agent_blocked_by_ratchet(
    broker, root_token, primary_identity, sub_identity
):
    narrowed_child = broker.exchange(
        parent_token=root_token,
        delegator_identity=primary_identity,
        delegatee_identity=sub_identity,
        new_caveats=[tool_name_caveat("read_calendar")],
    )
    decision = broker.authorize(
        narrowed_child,
        presenting_identity=sub_identity,
        proposed_tool_call=ProposedToolCall(tool_name="refund_payment", args={"amount": 999_999}),
    )
    assert not decision.allowed
    assert decision.reason_code == "CAVEAT_NOT_SATISFIED"
