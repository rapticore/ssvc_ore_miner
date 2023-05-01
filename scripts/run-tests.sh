#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

set -o errexit
set -o verbose

targets=(rapticoressvc setup.py)

# Find common security issues (https://bandit.readthedocs.io)
bandit --recursive "${targets[@]}" --skip B108 -ll

# Python code formatter (https://black.readthedocs.io)
# black --check --diff "${targets[@]}"

# Style guide enforcement (https://flake8.pycqa.org)
flake8 --config .flake8 "${targets[@]}"

# Sort imports (https://pycqa.github.io/isort)
#isort --settings-path .isort.cfg --check --diff "${targets[@]}"

# Static type checker (https://mypy.readthedocs.io)
#mypy --config-file .mypy.ini "${targets[@]}"

# Check for errors, enforce a coding standard, look for code smells (http://pylint.pycqa.org)
pylint "${targets[@]}"

# Check dependencies for security issues (https://pyup.io/safety)
#safety check \
#  -r backend/api/ssvc_ore_miner/requirements.txt \
#  -r requirements.txt \
#  -r requirements-dev.txt

# Report code complexity (https://radon.readthedocs.io)
#radon mi "${targets[@]}"

# Exit with non-zero status if code complexity exceeds thresholds (https://xenon.readthedocs.io)
#xenon --max-absolute A --max-modules A --max-average A "${targets[@]}"

# Run tests and measure code coverage (https://coverage.readthedocs.io)
pytest rapticoressvc/test/kevc_helper_test.py rapticoressvc/test/nvd_data_helper_test.py \
 rapticoressvc/test/s3_helper_test.py rapticoressvc/test/ssvc_ore_test.py \
 --envfile rapticoressvc/.env.test
#PYTHONPATH="${PWD}/backend/api/ssvc_ore_miner" \
#  coverage run --source "${PWD}" --omit ".venv/*,tests/*" -m unittest discover -v -s tests
