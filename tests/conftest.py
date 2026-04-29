"""Pytest configuration for Zero-Trust AI Gateway tests."""
import pytest
import asyncio


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()
