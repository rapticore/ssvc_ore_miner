import os
from unittest import mock


def mock_environment_variables(**envvars):
    return mock.patch.dict(os.environ, envvars)
