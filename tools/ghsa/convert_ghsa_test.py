# Copyright 2021 OSV Schema Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for the GHSA to OSV converter."""

import json
import os
import unittest

import convert_ghsa

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class ConverterTest(unittest.TestCase):
    """Converter unit tests."""

    def setUp(self):
        self.maxDiff = None  # pylint: disable=invalid-name

    def check_conversion(self, name):
        """Check OSV conversation against the expected result."""
        with open(os.path.join(TEST_DIR, f'{name}.json')) as handle:
            input_data = json.load(handle)

        output = convert_ghsa.convert(input_data)

        expected_path = os.path.join(TEST_DIR, f'{name}.osv.json')
        if os.getenv('TESTS_GENERATE'):
            with open(expected_path, 'w') as handle:
                handle.write(json.dumps(output, indent=2))

        with open(expected_path) as handle:
            expected = json.load(handle)

        self.assertDictEqual(expected, output)

    def test_full_ranges(self):
        """Test full (>= X, < Y) ranges."""
        self.check_conversion('full_ranges')

    def test_greater_than_equals_no_patch(self):
        """Test >=X without a patch."""
        self.check_conversion('greater_than_equals_no_patch')

    def test_multiple_ranges_in_package(self):
        """Test multiple ranges in the same package."""
        self.check_conversion('multiple_ranges_in_package')

    def test_less_than_equals_no_patch(self):
        """Test less than equals with no patch."""
        self.check_conversion('less_than_equals_no_patch')

    def test_less_than_equals_with_patch(self):
        """Test less than equals with patch."""
        self.check_conversion('less_than_equals_with_patch')

    def test_equals_no_patch(self):
        """Test =X versions with no patch."""
        self.check_conversion('equals_no_patch')

    def test_equals_with_patch(self):
        """Test =X versions with a patch."""
        self.check_conversion('equals_with_patch')

    def test_withdrawn(self):
        """Test a withdrawn entry."""
        self.check_conversion('withdrawn')

    def test_pypi_normalize(self):
        """Test normalization PyPI names."""
        self.check_conversion('pypi_normalize')

    def test_maven_greater_than(self):
        """Test Maven > ranges."""
        self.check_conversion('maven_greater_than')

    def test_maven_greater_than(self):
        """Test npm > ranges."""
        self.check_conversion('npm_greater_than')
