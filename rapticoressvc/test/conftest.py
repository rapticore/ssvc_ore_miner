import pytest

from rapticoressvc import config


@pytest.fixture(autouse=True)
def _reset_ssvc_config():
    """Reset the memoized config before and after each test so per-test env /
    configure() overrides never leak between tests."""
    config.reset_config()
    yield
    config.reset_config()
