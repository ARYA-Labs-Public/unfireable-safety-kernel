"""End-to-end adversarial run — exercises all 6 fixtures via the public surface.

Mirrors the Rust track's ``examples/reference_app_rs/tests/adversarial.rs``
suite (AC15). Each fixture asserts its specific attack vector is REJECTED.
"""

from __future__ import annotations

import pytest

from examples.testing.adversarial_fixtures import (
    ADVERSARIAL_FIXTURES,
    FIXTURE_IDS,
)


def test_fixture_taxonomy_matches_ac16_contract() -> None:
    """AC16 cross-language parity: exactly six fixtures, names locked in
    by the contract."""
    assert len(ADVERSARIAL_FIXTURES) == 6
    actual_ids = tuple(f.fixture_id for f in ADVERSARIAL_FIXTURES)
    assert actual_ids == FIXTURE_IDS, (
        f"AC16 fixture taxonomy mismatch.\n"
        f"Expected: {FIXTURE_IDS}\nGot: {actual_ids}"
    )


@pytest.mark.parametrize(
    "fixture",
    ADVERSARIAL_FIXTURES,
    ids=lambda f: f.fixture_id,
)
def test_adversarial_fixture_rejects_attack(fixture) -> None:
    """Each adversarial fixture must REJECT its attack vector.

    The fixture returns normally on success; raises on failure. We
    re-raise here so pytest reports the specific defect.
    """
    fixture.run()
