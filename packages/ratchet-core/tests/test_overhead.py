"""Overhead microbenchmark — mirrors Section 7.3 of arXiv:2609.00267.

Measures wall-clock time per Broker.authorize() and Broker.exchange() call.
Only asserts loose order-of-magnitude bounds here — microbenchmarks are
noisy across machines and CI runners. The precise numbers reported in the
README come from benchmarks/reproduce_paper_numbers.py, run manually.
"""

from __future__ import annotations

import time

from ratchet_core import (
    Broker,
    Ed25519WorkloadIdentity,
    ProposedToolCall,
    tool_name_caveat,
)

ITERATIONS = 200_000
WARMUP_ITERATIONS = 1_000
MAX_MICROS_PER_AUTHORIZE = 50.0
MAX_MICROS_PER_EXCHANGE = 100.0


def test_authorize_overhead_is_order_of_magnitude_microseconds():
    broker = Broker(secret=b"overhead-test-secret-00000000000000")
    primary = Ed25519WorkloadIdentity("primary-agent")
    token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat("read_calendar")],
    )
    call = ProposedToolCall(tool_name="read_calendar", args={})

    for _ in range(WARMUP_ITERATIONS):
        broker.authorize(token, presenting_identity=primary, proposed_tool_call=call)

    start = time.perf_counter()
    for _ in range(ITERATIONS):
        broker.authorize(token, presenting_identity=primary, proposed_tool_call=call)
    elapsed = time.perf_counter() - start

    micros_per_call = (elapsed / ITERATIONS) * 1_000_000
    print(f"\nauthorize(): {micros_per_call:.2f} us/call, {ITERATIONS / elapsed:,.0f} calls/sec")
    assert micros_per_call < MAX_MICROS_PER_AUTHORIZE


def test_exchange_overhead_is_order_of_magnitude_microseconds():
    broker = Broker(secret=b"overhead-test-secret-00000000000000")
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("sub-agent")
    token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat(".*")],
    )

    for _ in range(WARMUP_ITERATIONS):
        broker.exchange(
            parent_token=token,
            delegator_identity=primary,
            delegatee_identity=sub,
            new_caveats=[tool_name_caveat("read_calendar")],
        )

    start = time.perf_counter()
    for _ in range(ITERATIONS):
        broker.exchange(
            parent_token=token,
            delegator_identity=primary,
            delegatee_identity=sub,
            new_caveats=[tool_name_caveat("read_calendar")],
        )
    elapsed = time.perf_counter() - start

    micros_per_call = (elapsed / ITERATIONS) * 1_000_000
    print(f"\nexchange(): {micros_per_call:.2f} us/call, {ITERATIONS / elapsed:,.0f} calls/sec")
    assert micros_per_call < MAX_MICROS_PER_EXCHANGE
