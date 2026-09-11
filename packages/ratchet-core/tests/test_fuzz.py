"""Forged/mutated token fuzz test — mirrors Section 7.3 of arXiv:2609.00267.

Generates 200,000 random/mutated tokens across four strategies (random
bytes, bit-flipped valid tokens, truncated tokens, tokens with a caveat
tampered but the original signature kept) and asserts zero are ever
accepted by Broker.authorize(). Reports the acceptance count (target: 0).
"""

from __future__ import annotations

import dataclasses
import random

from ratchet_core import (
    Broker,
    Ed25519WorkloadIdentity,
    ProposedToolCall,
    RatchetMalformedToken,
    deserialize_token,
    serialize_token,
    tool_name_caveat,
)
from ratchet_core.caveats import Caveat, CaveatKind

FUZZ_ITERATIONS = 200_000
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _try_accept(broker: Broker, identity, blob: str, call: ProposedToolCall) -> int:
    try:
        token = deserialize_token(blob)
    except RatchetMalformedToken:
        return 0
    decision = broker.authorize(token, presenting_identity=identity, proposed_tool_call=call)
    return 1 if decision.allowed else 0


def test_fuzz_zero_forged_or_mutated_tokens_accepted():
    broker = Broker(secret=b"fuzz-test-secret-only-used-in-tests")
    primary = Ed25519WorkloadIdentity("primary-agent")
    valid_token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat("read_calendar")],
    )
    valid_blob = serialize_token(valid_token)
    call = ProposedToolCall(tool_name="read_calendar", args={})

    rng = random.Random(1337)
    accepted = 0

    for i in range(FUZZ_ITERATIONS):
        strategy = i % 4

        if strategy == 0:  # pure random bytes
            length = rng.randint(8, len(valid_blob) + 32)
            candidate = "".join(rng.choice(_ALPHABET) for _ in range(length))
            accepted += _try_accept(broker, primary, candidate, call)

        elif strategy == 1:  # bit-flipped (character-substituted) valid token
            chars = list(valid_blob)
            # Distinct indices, each replaced with a non-original character:
            # guarantees the result differs from valid_blob in at least one
            # position. Repeating an index could let a second flip cancel the
            # first back to the original character, reproducing the valid
            # token byte-for-byte -- which is correctly accepted and isn't a
            # forgery at all.
            for idx in rng.sample(range(len(chars)), rng.randint(1, 5)):
                chars[idx] = rng.choice(_ALPHABET.replace(chars[idx], ""))
            candidate = "".join(chars)
            accepted += _try_accept(broker, primary, candidate, call)

        elif strategy == 2:  # truncated valid token
            cut = rng.randint(1, max(1, len(valid_blob) - 1))
            accepted += _try_accept(broker, primary, valid_blob[:cut], call)

        else:  # tampered caveat, original (now-invalid) signature kept
            tampered_hop = tuple(
                Caveat(kind=CaveatKind.TOOL_NAME, params={"pattern": ".*"})
                if c.kind is CaveatKind.TOOL_NAME
                else c
                for c in valid_token.caveats_by_hop[0]
            )
            tampered = dataclasses.replace(valid_token, caveats_by_hop=(tampered_hop,))
            decision = broker.authorize(
                tampered, presenting_identity=primary, proposed_tool_call=call
            )
            if decision.allowed:
                accepted += 1

    print(f"\nfuzz: {accepted}/{FUZZ_ITERATIONS} forged/mutated tokens accepted (target: 0)")
    assert accepted == 0
