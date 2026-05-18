"""Pre-run modifier that skips specific tests by name.

Usage with Robot Framework:
    robot --prerunmodifier skip_tests.py tests/
    robot --prerunmodifier skip_tests.py:extra_test_to_skip tests/

Known failures are embedded below. Additional test names can be passed
as arguments to skip on top of the built-in list.
"""

from robot.api import SuiteVisitor

# Known upstream test suite bugs: mapping of test name to skip reason.
KNOWN_FAILURES = {
    # Test suite bug (tests/cert_conf_tests.robot): expects badRequest but RFC 9483 §3.5
    # mandates badDataFormat for missing transactionID. The correct test in
    # tests/lwcmp.robot ("FailInfo Bit Must Be badDataFormat For Missing transactionID") passes.
    "CA MUST Reject CertConf with omitted transactionID":
        "NOTE: Seems like test suite bug: expects badRequest but RFC 9483 §3.5 mandates badDataFormat",
    # pyasn1 bug (pyasn1/pyasn1#53) in tests/lwcmp.robot: encoder.encode() mutates
    # objects, crashing subsequent __eq__.
    "CA Must Validate The Received PKI Message":
        "NOTE: seems like pyasn1 bug (pyasn1/pyasn1#53): encoder.encode() mutates objects",
}


class skip_tests(SuiteVisitor):

    def __init__(self, *test_names):
        self.skip_map = {name.lower(): reason for name, reason in KNOWN_FAILURES.items()}
        for name in test_names:
            self.skip_map[name.lower()] = "Skipped via pre-run modifier argument"

    def start_suite(self, suite):
        for test in suite.tests:
            reason = self.skip_map.get(test.name.lower())
            if reason:
                test.body.clear()
                test.body.create_keyword("BuiltIn.Skip", args=[reason])
