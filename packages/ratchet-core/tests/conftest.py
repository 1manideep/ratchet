"""Shared fixtures for ratchet-core tests."""

from __future__ import annotations

import pytest

from ratchet_core import (
    Broker,
    Ed25519WorkloadIdentity,
    max_depth_caveat,
    tool_name_caveat,
)

TEST_SECRET = b"test-secret-only-used-in-unit-tests"


@pytest.fixture
def broker() -> Broker:
    return Broker(secret=TEST_SECRET)


@pytest.fixture
def primary_identity() -> Ed25519WorkloadIdentity:
    return Ed25519WorkloadIdentity("primary-agent")


@pytest.fixture
def sub_identity() -> Ed25519WorkloadIdentity:
    return Ed25519WorkloadIdentity("sub-agent")


@pytest.fixture
def attacker_identity() -> Ed25519WorkloadIdentity:
    return Ed25519WorkloadIdentity("attacker")


@pytest.fixture
def root_token(broker, primary_identity):
    """A root token scoped to three tools, max delegation depth 5."""
    return broker.issue(
        human_identity="alice@example.com",
        primary_identity=primary_identity,
        caveats=[
            tool_name_caveat(r"send_email|read_calendar|refund_payment"),
            max_depth_caveat(5),
        ],
        ttl_seconds=900,
    )
