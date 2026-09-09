"""Ported from the newer eval harness (clone susvibes/core/logs.py).

A test run's pass/failure outcome as a comparable value, so the func (count-based) and
sec (per-case, for flags.gen_test instances) runs read the same in `Task.evaluate`:

- PassFailureCount  -> a failure count; the stored `expected_pf` threshold is an int.
- PassFailureCases  -> a {case: passed} map; the stored `expected_pf` threshold is the
                       list of security test-cases expected to pass.

A non-completed run compares as infinitely broken (never passes).
"""
import json
from abc import ABC, abstractmethod

from susvibes.env_specs.constants import TestStatus


def extract_json_object(text: str) -> dict | None:
    """The last top-level JSON object embedded in `text`, or None. Scans past any prose,
    fences, or stray scalars the sec-test harness may print around the object."""
    decoder = json.JSONDecoder()
    obj, i, n = None, 0, len(text)
    while i < n:
        if text[i] == "{":
            try:
                candidate, end = decoder.raw_decode(text, i)
            except json.JSONDecodeError:
                i += 1
                continue
            if isinstance(candidate, dict):
                obj, i = candidate, end
                continue
        i += 1
    return obj


class PassFailure(ABC):
    def __init__(self, status: TestStatus):
        self.status = status

    def completed(self) -> bool:
        return self.status == TestStatus.COMPLETION

    @abstractmethod
    def breaks_more_than(self, other: "PassFailure") -> bool:
        """Whether this run is strictly more broken than `other` (a non-completed run always is)."""

    @abstractmethod
    def capped_by(self, other: "PassFailure") -> "PassFailure":
        """This expected threshold capped at `other` (the lesser-broken of the two)."""

    @abstractmethod
    def get_raw(self):
        """The bare JSON-serializable value to store as the expected threshold."""

    @classmethod
    def from_raw(cls, raw) -> "PassFailure":
        """A stored raw value: a list of passed cases -> PassFailureCases, else a count."""
        if isinstance(raw, list):
            return PassFailureCases(TestStatus.COMPLETION, {case: True for case in raw})
        return PassFailureCount(TestStatus.COMPLETION, raw)

    @staticmethod
    def add_raw(a, b):
        """Combine two expected-raw thresholds across eval runs: both counts -> sum, both
        case lists -> de-duped union; a count mixed with a list -> the list wins."""
        if isinstance(a, list) and isinstance(b, list):
            return list(dict.fromkeys(a + b))
        if isinstance(a, list) or isinstance(b, list):
            return a if isinstance(a, list) else b
        return a + b


class PassFailureCount(PassFailure):
    def __init__(self, status: TestStatus, failures: int):
        super().__init__(status)
        self.failures = failures

    def breaks_more_than(self, other):
        return not self.completed() or self.failures > other.failures

    def capped_by(self, other):
        return PassFailureCount(TestStatus.COMPLETION, min(self.failures, other.failures))

    def get_raw(self):
        return self.failures


class PassFailureCases(PassFailure):
    """A {case: passed} map; 'breaks' are the common cases this run fails that `other` passes."""

    def __init__(self, status: TestStatus, cases: dict):
        super().__init__(status)
        self.cases = cases

    def _distinguishing(self, other: "PassFailureCases") -> set:
        return {case for case in self.cases.keys() & other.cases.keys()
            if self.cases[case] is False and other.cases[case] is True}

    def breaks_more_than(self, other):
        return not self.completed() or bool(self._distinguishing(other))

    def capped_by(self, other):
        cases = dict(self.cases)
        for case, passed in other.cases.items():
            if passed is True and cases.get(case) is not True:
                cases[case] = True
        return PassFailureCases(TestStatus.COMPLETION, cases)

    def get_raw(self):
        return [case for case, passed in self.cases.items() if passed is True]
