"""Deterministic rules engine (L6 reflex) over Event v3.0.

Design constraints:
  * rules are **data** (JSON), never code — no eval, no dynamic import;
  * every rule has an id, severity, ATT&CK technique and a fixture-backed test;
  * matching is a conjunction of field conditions (equality, set membership,
    regex, prefix/suffix/contains, numeric comparison);
  * windowed rules count matching events per group inside a time window
    (behavioural detections: mass writes, brute force);
  * correlation rules require several conditions to occur for the same entity
    (`actor.pid` or the process tree) inside a window;
  * a match yields a `Verdict` v3.0 (detector="rule"), which the policy layer
    turns into actions. The engine never executes anything.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable
from uuid import uuid4

from schemas.v3 import SEVERITIES, Verdict

KNOWN_OPERATORS = {"regex", "in", "startswith", "endswith", "contains",
                   "gt", "lt", "gte", "lte", "equals",
                   "not_regex", "not_startswith", "not_contains"}

# Fields a rule may reference (nested paths, dot-separated).
ALLOWED_FIELDS = {
    "platform", "source", "layer", "category", "action",
    "actor.pid", "actor.name", "actor.path", "actor.cmdline_redacted", "actor.signature",
    "actor.sha256", "actor.uid", "actor.sid", "actor.session", "actor.ppid",
    "object.type", "object.path", "object.sha256", "object.ip", "object.port", "object.proto",
    "user.name", "user.domain",
    "host.host_id", "host.os", "host.version", "host.arch",
    "integrity.level", "integrity.verified",
    "kernel_meta.irql", "kernel_meta.callback_type", "kernel_meta.trust",
    "platform_data",  # any nested key: platform_data.<key> validated at runtime
}

MAX_REGEX_LEN = 200
# Input side of the same problem: matching is bounded so one hostile string
# cannot blow up the reflex path (see DEVLOG F11 crash investigation).
MAX_REGEX_INPUT = 512


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    technique: str
    layer: str
    match: dict[str, Any]
    reason_code: str
    prevention: bool = False
    window_sec: float | None = None
    threshold: int | None = None
    group_by: str = "host.host_id"
    enabled: bool = True
    # multi-event correlation: all requirements must appear for the same group
    # value inside window_sec; `match` is then optional
    correlate: dict[str, Any] | None = None

    @property
    def windowed(self) -> bool:
        return self.window_sec is not None or self.threshold is not None

    @property
    def correlated(self) -> bool:
        return self.correlate is not None


def _get(payload: dict, path: str) -> Any:
    cur: Any = payload
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _match_condition(actual: Any, condition: Any) -> bool:
    if isinstance(condition, dict):
        for op, operand in condition.items():
            if op not in KNOWN_OPERATORS:
                raise ValueError(f"unknown operator: {op}")
            if op == "regex":
                if actual is None:
                    return False
                if not re.search(str(operand), str(actual)[:MAX_REGEX_INPUT]):
                    return False
            elif op == "in":
                if actual not in _as_list(operand):
                    return False
            elif op == "startswith":
                if actual is None or not str(actual).lower().startswith(str(operand).lower()):
                    return False
            elif op == "endswith":
                if actual is None or not str(actual).lower().endswith(str(operand).lower()):
                    return False
            elif op == "contains":
                if actual is None or str(operand).lower() not in str(actual).lower():
                    return False
            elif op == "not_regex":
                if actual is None or re.search(str(operand),
                                               str(actual)[:MAX_REGEX_INPUT]):
                    return False
            elif op == "not_startswith":
                if actual is None or str(actual).lower().startswith(str(operand).lower()):
                    return False
            elif op == "not_contains":
                if actual is None or str(operand).lower() in str(actual).lower():
                    return False
            elif op == "gt":
                if actual is None or not float(actual) > float(operand):
                    return False
            elif op == "lt":
                if actual is None or not float(actual) < float(operand):
                    return False
            elif op == "gte":
                if actual is None or not float(actual) >= float(operand):
                    return False
            elif op == "lte":
                if actual is None or not float(actual) <= float(operand):
                    return False
            elif op == "equals":
                if actual != operand:
                    return False
        return True
    if isinstance(condition, list):
        return actual in condition
    if isinstance(condition, bool):
        return actual is condition
    if actual is None:
        return False
    return str(actual).lower() == str(condition).lower()


def rule_matches(rule: Rule, payload: dict) -> bool:
    return conditions_match(rule.match, payload)


def conditions_match(conditions: dict, payload: dict) -> bool:
    for path, condition in conditions.items():
        if not _match_condition(_get(payload, path), condition):
            return False
    return True


# --------------------------------------------------------------------------- lint
def _lint_condition(rule_id: str, condition: Any, problems: list[str]) -> None:
    if not isinstance(condition, dict):
        return
    for op, operand in condition.items():
        if op not in KNOWN_OPERATORS:
            problems.append(f"{rule_id}: unknown operator {op!r}")
        if op == "regex":
            if len(str(operand)) > MAX_REGEX_LEN:
                problems.append(f"{rule_id}: regex too long (>{MAX_REGEX_LEN})")
            if re.search(r"\([^)]*[+*][^)]*\)[+*]", str(operand)):
                problems.append(f"{rule_id}: nested quantifier in regex (ReDoS shape)")
            try:
                re.compile(str(operand))
            except re.error as exc:
                problems.append(f"{rule_id}: bad regex: {exc}")


def lint_rules(rules: Iterable[Rule], known_techniques: set[str] | None = None) -> list[str]:
    """Validate rules; returns a list of problems (empty == clean)."""
    problems: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if not rule.id or not re.fullmatch(r"[A-Z0-9][A-Z0-9\-_.]{4,63}", rule.id):
            problems.append(f"{rule.id!r}: id must be UPPER-case, 5..64 chars")
        if rule.id in seen:
            problems.append(f"{rule.id}: duplicate id")
        seen.add(rule.id)
        if rule.severity not in SEVERITIES:
            problems.append(f"{rule.id}: bad severity {rule.severity!r}")
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", rule.technique):
            problems.append(f"{rule.id}: bad ATT&CK technique {rule.technique!r}")
        if known_techniques is not None and rule.technique not in known_techniques:
            problems.append(f"{rule.id}: technique {rule.technique} not in coverage matrix")
        if not rule.title.strip():
            problems.append(f"{rule.id}: empty title")
        if not rule.match and not rule.correlated:
            problems.append(f"{rule.id}: empty match")
        for path, condition in rule.match.items():
            if path != "platform_data" and path not in ALLOWED_FIELDS and not path.startswith("platform_data."):
                problems.append(f"{rule.id}: unknown field {path!r}")
            if path.startswith("platform_data.") and path.count(".") < 1:
                problems.append(f"{rule.id}: malformed platform_data path {path!r}")
            _lint_condition(rule.id, condition, problems)
        if rule.correlated:
            spec = rule.correlate or {}
            require = spec.get("require")
            if not isinstance(require, list) or len(require) < 2:
                problems.append(f"{rule.id}: correlate.require needs >= 2 conditions")
            elif not all(isinstance(item, dict) and item for item in require):
                problems.append(f"{rule.id}: correlate.require items must be non-empty objects")
            else:
                for item in require:
                    for path, condition in item.items():
                        if path != "platform_data" and path not in ALLOWED_FIELDS and not path.startswith("platform_data."):
                            problems.append(f"{rule.id}: unknown field {path!r} in correlate")
                        _lint_condition(rule.id, condition, problems)
            if not isinstance(spec.get("window_sec"), (int, float)) or spec["window_sec"] <= 0:
                problems.append(f"{rule.id}: correlate.window_sec must be > 0")
            if spec.get("group_by", "actor.pid") not in ALLOWED_FIELDS and \
                    spec.get("group_by") != "process_tree":
                problems.append(f"{rule.id}: unknown correlate.group_by")
        if rule.windowed:
            if rule.window_sec is None or rule.threshold is None:
                problems.append(f"{rule.id}: windowed rule needs both window_sec and threshold")
            elif rule.window_sec <= 0 or rule.threshold < 2:
                problems.append(f"{rule.id}: window/threshold out of range")
            if rule.group_by not in ALLOWED_FIELDS:
                problems.append(f"{rule.id}: unknown group_by {rule.group_by!r}")
    return problems


def load_rules(paths: Iterable[str]) -> list[Rule]:
    rules: list[Rule] = []
    for path in paths:
        # utf-8-sig: tolerate a BOM (Windows editors add one silently)
        with open(path, encoding="utf-8-sig") as fh:
            payload = json.load(fh)
        items = payload if isinstance(payload, list) else payload.get("rules", [])
        for item in items:
            rules.append(Rule(**item))
    return rules


# --------------------------------------------------------------------------- engine
@dataclass
class RuleEngine:
    rules: list[Rule]
    now_fn: Any = None
    _windows: dict[tuple[str, str], deque] = field(default_factory=lambda: defaultdict(deque), repr=False)
    _counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # (rule_id, group) -> {requirement_index: last_seen}
    _corr: dict[tuple[str, str], dict[int, float]] = field(
        default_factory=lambda: defaultdict(dict), repr=False)
    # pid -> ppid, learned from every event that carries actor.pid/actor.ppid
    _parents: dict[int, int] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.now_fn is None:
            import time
            self.now_fn = time.monotonic
        self.rules = [r for r in self.rules if r.enabled]
        problems = lint_rules(self.rules)
        if problems:
            raise ValueError("invalid rules: " + "; ".join(problems))

    def evaluate(self, event: Any) -> list[Verdict]:
        """Evaluate one Event; returns verdicts (usually zero or one)."""
        payload = event.model_dump(mode="json")
        now = self.now_fn()
        self._remember_parent(payload)
        out: list[Verdict] = []
        for rule in self.rules:
            if rule.correlated:
                if not self._correlation_hit(rule, payload, now):
                    continue
            elif not rule_matches(rule, payload):
                continue
            elif rule.windowed:
                group = str(_get(payload, rule.group_by))
                key = (rule.id, group)
                bucket = self._windows[key]
                bucket.append(now)
                while bucket and now - bucket[0] > float(rule.window_sec):
                    bucket.popleft()
                if len(bucket) < int(rule.threshold):
                    continue
                bucket.clear()
            self._counts[rule.id] += 1
            out.append(Verdict(
                verdict_id=uuid4(),
                trace_id=event.trace_id,
                event_id=event.event_id,
                detector="rule",
                rule_id=rule.id,
                platform=event.platform,
                confidence=1.0,
                severity=rule.severity,          # type: ignore[arg-type]
                reason_code=rule.reason_code,
                reason_text=rule.title,
            ))
        return out

    def _remember_parent(self, payload: dict) -> None:
        pid = _get(payload, "actor.pid")
        ppid = _get(payload, "actor.ppid")
        if isinstance(pid, int) and isinstance(ppid, int) and ppid > 0 and pid != ppid:
            self._parents[pid] = ppid

    def _root_pid(self, pid: Any, depth: int = 8) -> str:
        """Walk up to the root ancestor; bounded and cycle-safe."""
        current = pid
        for _ in range(depth):
            if not isinstance(current, int):
                break
            parent = self._parents.get(current)
            if parent is None or parent == current:
                break
            current = parent
        return str(current)

    def _group_key(self, rule: Rule, payload: dict) -> str:
        spec = rule.correlate or {}
        mode = spec.get("group_by", "actor.pid")
        if mode == "process_tree":
            return "tree:" + self._root_pid(_get(payload, "actor.pid"))
        return str(_get(payload, mode))

    def _correlation_hit(self, rule: Rule, payload: dict, now: float) -> bool:
        """True when every requirement of a correlation rule was seen inside the window."""
        spec = rule.correlate or {}
        window = float(spec["window_sec"])
        group = self._group_key(rule, payload)
        state = self._corr[(rule.id, group)]
        for index, conditions in enumerate(spec["require"]):
            if conditions_match(conditions, payload):
                state[index] = now
        for index in [i for i, ts in state.items() if now - ts > window]:
            state.pop(index, None)
        if len(state) == len(spec["require"]):
            state.clear()          # one verdict per completed correlation
            return True
        return False

    def counts(self) -> dict[str, int]:
        return dict(self._counts)
