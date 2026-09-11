"""Blast-radius simulation — mirrors Section 7.3 of arXiv:2609.00267.

Builds a synthetic environment of TOOL_COUNT x RESOURCE_COUNT actions
(90 x 90 = 8,100, matching the paper's environment size) and runs
randomized delegation scenarios comparing bearer-token delegation (no
attenuation — a sub-agent inherits the parent's full scope unchanged)
against Ratchet-attenuated delegation.

Reachable-action counts are derived analytically from the same
fullmatch-regex logic `evaluate_caveat` uses for TOOL_NAME/RESOURCE
caveats: because those caveats are ANDed and independent, reachable =
|matching tools| x |matching resources|. That is what makes 2,000
scenarios over an 8,100-action environment fast to run. Each scenario
still exercises the real Broker.authorize() with one in-scope and one
out-of-scope action, to confirm the broker's actual behavior agrees with
the analytic count.
"""

from __future__ import annotations

import random
import re

from ratchet_core import (
    Broker,
    Ed25519WorkloadIdentity,
    ProposedToolCall,
    resource_caveat,
    tool_name_caveat,
)

TOOL_COUNT = 90
RESOURCE_COUNT = 90
TOTAL_ACTIONS = TOOL_COUNT * RESOURCE_COUNT  # 8,100, matching the paper
SCENARIO_COUNT = 2_000

TOOLS = [f"tool_{i:03d}" for i in range(TOOL_COUNT)]
RESOURCES = [f"resource_{j:03d}" for j in range(RESOURCE_COUNT)]


def _matching_count(pattern: str, universe: list[str]) -> int:
    return sum(1 for item in universe if re.fullmatch(pattern, item) is not None)


def _run_scenarios(
    broker: Broker, primary, sub, tools: list[str], resources: list[str], rng: random.Random
) -> tuple[list[int], list[int]]:
    bearer_reach: list[int] = []
    ratchet_reach: list[int] = []

    for _ in range(SCENARIO_COUNT):
        root = broker.issue(
            human_identity="alice@example.com",
            primary_identity=primary,
            caveats=[tool_name_caveat(".*"), resource_caveat(".*")],
        )

        # --- bearer-token delegation: sub-agent gets the identical, unattenuated token ---
        bearer_reach.append(len(tools) * len(resources))
        spot_tool, spot_resource = rng.choice(tools), rng.choice(resources)
        bearer_decision = broker.authorize(
            root,
            presenting_identity=primary,  # unchanged holder -- this *is* the vulnerability
            proposed_tool_call=ProposedToolCall(
                tool_name=spot_tool, args={}, resource=spot_resource
            ),
        )
        assert bearer_decision.allowed  # every action is reachable, by construction

        # --- Ratchet-attenuated delegation: narrowed to this sub-agent's one task ---
        task_tool = rng.choice(tools)
        task_resource = rng.choice(resources)
        # ~50% single-tool tasks, ~50% two-tool tasks sharing one resource --
        # a realistic mix of single- and multi-step sub-tasks.
        if rng.random() < 0.5:
            tool_pattern = re.escape(task_tool)
        else:
            other_tool = rng.choice([t for t in tools if t != task_tool])
            tool_pattern = f"{re.escape(task_tool)}|{re.escape(other_tool)}"
        resource_pattern = re.escape(task_resource)

        child = broker.exchange(
            parent_token=root,
            delegator_identity=primary,
            delegatee_identity=sub,
            new_caveats=[tool_name_caveat(tool_pattern), resource_caveat(resource_pattern)],
        )
        ratchet_reach.append(
            _matching_count(tool_pattern, tools) * _matching_count(resource_pattern, resources)
        )

        allowed_decision = broker.authorize(
            child,
            presenting_identity=sub,
            proposed_tool_call=ProposedToolCall(
                tool_name=task_tool, args={}, resource=task_resource
            ),
        )
        assert allowed_decision.allowed

        out_of_scope_tool = rng.choice([t for t in tools if re.fullmatch(tool_pattern, t) is None])
        denied_decision = broker.authorize(
            child,
            presenting_identity=sub,
            proposed_tool_call=ProposedToolCall(
                tool_name=out_of_scope_tool, args={}, resource=task_resource
            ),
        )
        assert not denied_decision.allowed

    return bearer_reach, ratchet_reach


def test_blast_radius_bearer_vs_ratchet():
    rng = random.Random(2026)
    broker = Broker(secret=b"blast-radius-test-secret-0000000000")
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("sub-agent")

    bearer_reach, ratchet_reach = _run_scenarios(broker, primary, sub, TOOLS, RESOURCES, rng)

    bearer_mean = sum(bearer_reach) / len(bearer_reach)
    ratchet_mean = sum(ratchet_reach) / len(ratchet_reach)

    print(f"\nblast radius over {TOTAL_ACTIONS} actions, {SCENARIO_COUNT} scenarios:")
    print(f"  bearer delegation mean reachable actions:  {bearer_mean:.1f}")
    print(f"  ratchet delegation mean reachable actions: {ratchet_mean:.1f}")

    assert bearer_mean == TOTAL_ACTIONS
    assert ratchet_mean < 10  # paper reports ~1.5; asserting order-of-magnitude confinement


def test_blast_radius_ratchet_reach_is_independent_of_environment_size():
    """Defended reach should be bounded by the task, not by environment size."""
    rng = random.Random(7)
    broker = Broker(secret=b"blast-radius-size-test-secret-00000")
    primary = Ed25519WorkloadIdentity("primary-agent")
    sub = Ed25519WorkloadIdentity("sub-agent")

    big_tools = [f"tool_{i:04d}" for i in range(400)]
    big_resources = [f"resource_{j:04d}" for j in range(400)]  # 160,000 actions

    bearer_reach, ratchet_reach = _run_scenarios(
        broker, primary, sub, big_tools, big_resources, rng
    )
    bearer_mean = sum(bearer_reach) / len(bearer_reach)
    ratchet_mean = sum(ratchet_reach) / len(ratchet_reach)

    assert bearer_mean == len(big_tools) * len(big_resources)  # scales with environment size
    assert ratchet_mean < 10  # stays small even though the environment is ~20x bigger
