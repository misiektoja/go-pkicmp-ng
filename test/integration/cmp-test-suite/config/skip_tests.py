"""Pre-run modifier that skips specific tests by name.

Usage with Robot Framework:
    robot --prerunmodifier skip_tests.py:test1:test2 tests/

This uses Robot Framework's SuiteVisitor API to add the robot:skip tag
to tests matching the given names. Matching is case-insensitive.
"""

from robot.api import SuiteVisitor


class skip_tests(SuiteVisitor):

    def __init__(self, *test_names):
        self.test_names = [name.lower() for name in test_names]

    def start_suite(self, suite):
        for test in suite.tests:
            if test.name.lower() in self.test_names:
                test.tags.add("robot:skip")
