"""benchmarks/reproduce_paper_numbers.py

Runs all four evaluation axes from Section 7.3 of arXiv:2609.00267 against
this machine and prints a results table -- this is what populates the
README's benchmark table and any launch post. Run manually; these are not
CI assertions (see packages/ratchet-core/tests/test_overhead.py for the
loose, machine-independent CI checks).

Usage:
    uv run --package ratchet-authz-core python benchmarks/reproduce_paper_numbers.py
"""

from __future__ import annotations

import random
import re
import time

from ratchet_core import (
    Broker,
    Ed25519WorkloadIdentity,
    ProposedToolCall,
    RatchetMalformedToken,
    deserialize_token,
    resource_caveat,
    serialize_token,
    tool_name_caveat,
)

OVERHEAD_ITERATIONS = 200_000
FUZZ_ITERATIONS = 200_000
BLAST_RADIUS_SCENARIOS = 2_000
BLAST_RADIUS_TOOLS = 90
BLAST_RADIUS_RESOURCES = 90
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _new_broker() -> Broker:
    return Broker(secret=b"benchmark-secret-only-used-here-0000")


def run_overhead() -> dict[str, float]:
    broker = _new_broker()
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("sub-agent")
    token = broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary,
        caveats=[tool_name_caveat(".*")],
    )
    call = ProposedToolCall(tool_name="read_calendar", args={})

    for _ in range(1_000):
        broker.authorize(token, presenting_identity=primary, proposed_tool_call=call)
    start = time.perf_counter()
    for _ in range(OVERHEAD_ITERATIONS):
        broker.authorize(token, presenting_identity=primary, proposed_tool_call=call)
    authorize_elapsed = time.perf_counter() - start

    for _ in range(1_000):
        broker.exchange(
            parent_token=token,
            delegator_identity=primary,
            delegatee_identity=sub,
            new_caveats=[tool_name_caveat("read_calendar")],
        )
    start = time.perf_counter()
    for _ in range(OVERHEAD_ITERATIONS):
        broker.exchange(
            parent_token=token,
            delegator_identity=primary,
            delegatee_identity=sub,
            new_caveats=[tool_name_caveat("read_calendar")],
        )
    exchange_elapsed = time.perf_counter() - start

    return {
        "authorize_us": (authorize_elapsed / OVERHEAD_ITERATIONS) * 1_000_000,
        "authorize_per_sec": OVERHEAD_ITERATIONS / authorize_elapsed,
        "exchange_us": (exchange_elapsed / OVERHEAD_ITERATIONS) * 1_000_000,
        "exchange_per_sec": OVERHEAD_ITERATIONS / exchange_elapsed,
    }


def run_fuzz() -> dict[str, int]:
    import dataclasses

    from ratchet_core.caveats import Caveat, CaveatKind

    broker = _new_broker()
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

    def try_accept(blob: str) -> int:
        try:
            token = deserialize_token(blob)
        except RatchetMalformedToken:
            return 0
        decision = broker.authorize(token, presenting_identity=primary, proposed_tool_call=call)
        return 1 if decision.allowed else 0

    for i in range(FUZZ_ITERATIONS):
        strategy = i % 4
        if strategy == 0:
            length = rng.randint(8, len(valid_blob) + 32)
            accepted += try_accept("".join(rng.choice(_ALPHABET) for _ in range(length)))
        elif strategy == 1:
            chars = list(valid_blob)
            for idx in rng.sample(range(len(chars)), rng.randint(1, 5)):
                chars[idx] = rng.choice(_ALPHABET.replace(chars[idx], ""))
            accepted += try_accept("".join(chars))
        elif strategy == 2:
            cut = rng.randint(1, max(1, len(valid_blob) - 1))
            accepted += try_accept(valid_blob[:cut])
        else:
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
            accepted += 1 if decision.allowed else 0

    return {"accepted": accepted, "total": FUZZ_ITERATIONS}


def run_blast_radius() -> dict[str, float]:
    broker = _new_broker()
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("sub-agent")
    rng = random.Random(2026)

    tools = [f"tool_{i:03d}" for i in range(BLAST_RADIUS_TOOLS)]
    resources = [f"resource_{j:03d}" for j in range(BLAST_RADIUS_RESOURCES)]

    def matching_count(pattern: str, universe: list[str]) -> int:
        return sum(1 for item in universe if re.fullmatch(pattern, item) is not None)

    bearer_reach: list[int] = []
    ratchet_reach: list[int] = []

    for _ in range(BLAST_RADIUS_SCENARIOS):
        root = broker.issue(
            human_identity="alice@example.com",
            primary_identity=primary,
            caveats=[tool_name_caveat(".*"), resource_caveat(".*")],
        )
        bearer_reach.append(len(tools) * len(resources))

        task_tool = rng.choice(tools)
        task_resource = rng.choice(resources)
        if rng.random() < 0.5:
            tool_pattern = re.escape(task_tool)
        else:
            other_tool = rng.choice([t for t in tools if t != task_tool])
            tool_pattern = f"{re.escape(task_tool)}|{re.escape(other_tool)}"

        broker.exchange(
            parent_token=root,
            delegator_identity=primary,
            delegatee_identity=sub,
            new_caveats=[tool_name_caveat(tool_pattern), resource_caveat(re.escape(task_resource))],
        )
        ratchet_reach.append(
            matching_count(tool_pattern, tools)
            * matching_count(re.escape(task_resource), resources)
        )

    return {
        "total_actions": len(tools) * len(resources),
        "scenarios": BLAST_RADIUS_SCENARIOS,
        "bearer_mean": sum(bearer_reach) / len(bearer_reach),
        "ratchet_mean": sum(ratchet_reach) / len(ratchet_reach),
    }


def main() -> None:
    print("Ratchet -- reproducing arXiv:2609.00267 Section 7.3 evaluation numbers")
    print("=" * 78)

    overhead = run_overhead()
    print("\n[1/3] Overhead")
    print(
        f"  authorize(): {overhead['authorize_us']:.2f} us/call, {overhead['authorize_per_sec']:,.0f} decisions/sec"
    )
    print(
        f"  exchange():  {overhead['exchange_us']:.2f} us/call, {overhead['exchange_per_sec']:,.0f} exchanges/sec"
    )

    fuzz = run_fuzz()
    print("\n[2/3] Fuzz (forged/mutated token acceptance)")
    print(f"  accepted: {fuzz['accepted']}/{fuzz['total']} (target: 0)")

    blast = run_blast_radius()
    print("\n[3/3] Blast radius")
    print(f"  environment: {blast['total_actions']} actions, {blast['scenarios']} scenarios")
    print(f"  bearer delegation mean reachable actions:  {blast['bearer_mean']:.1f}")
    print(f"  ratchet delegation mean reachable actions: {blast['ratchet_mean']:.1f}")

    print("\n" + "=" * 78)
    print("README summary table:\n")
    print("| Metric | Result |")
    print("|---|---|")
    print(
        f"| authorize() latency | {overhead['authorize_us']:.2f} us/call ({overhead['authorize_per_sec']:,.0f}/sec) |"
    )
    print(
        f"| exchange() latency | {overhead['exchange_us']:.2f} us/call ({overhead['exchange_per_sec']:,.0f}/sec) |"
    )
    print(f"| Forged/mutated tokens accepted | {fuzz['accepted']} / {fuzz['total']} |")
    print(
        f"| Blast radius (bearer delegation) | {blast['bearer_mean']:.1f} / {blast['total_actions']} actions |"
    )
    print(
        f"| Blast radius (Ratchet delegation) | {blast['ratchet_mean']:.1f} / {blast['total_actions']} actions |"
    )
    print(
        "\nNote: the 11-attack and T1-T4 adversarial-robustness suite is enforced as\n"
        "pytest assertions, not a benchmark metric -- see "
        "packages/ratchet-core/tests/test_attacks.py\n(run `pytest packages/ratchet-core/tests/test_attacks.py -v` "
        "for the pass/fail table)."
    )


if __name__ == "__main__":
    main()
