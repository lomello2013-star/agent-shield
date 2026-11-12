"""Harden regex matching: cap the input length and reject nested quantifiers.

The 1800 s soak crash left a stack inside `_match_condition`, i.e. inside `re`. Even
though the current rules have no obviously catastrophic patterns, an attacker-controlled
string is what gets matched, so two cheap defences are added:

  * the *input* is truncated before matching (bounded work per event);
  * the lint rejects nested quantifiers like `(a+)+`, the classic ReDoS shape.
"""

import io

PATH = "core/rules.py"
text = io.open(PATH, encoding="utf-8").read()

if "MAX_REGEX_INPUT" not in text:
    text = text.replace(
        "MAX_REGEX_LEN = 200",
        "MAX_REGEX_LEN = 200\n"
        "# Input side of the same problem: matching is bounded so one hostile string\n"
        "# cannot blow up the reflex path (see DEVLOG F11 crash investigation).\n"
        "MAX_REGEX_INPUT = 512", 1)

old_regex = '''            if op == "regex":
                if actual is None:
                    return False
                if not re.search(str(operand), str(actual)):
                    return False'''
new_regex = '''            if op == "regex":
                if actual is None:
                    return False
                if not re.search(str(operand), str(actual)[:MAX_REGEX_INPUT]):
                    return False'''
if old_regex not in text:
    raise SystemExit("regex branch anchor not found")
text = text.replace(old_regex, new_regex, 1)

old_not = '''            elif op == "not_regex":
                if actual is None or re.search(str(operand), str(actual)):
                    return False'''
new_not = '''            elif op == "not_regex":
                if actual is None or re.search(str(operand),
                                               str(actual)[:MAX_REGEX_INPUT]):
                    return False'''
if old_not in text:
    text = text.replace(old_not, new_not, 1)

# lint: nested quantifier is the classic ReDoS shape and has no use in detection rules
old_lint = '''        if op == "regex":
            if len(str(operand)) > MAX_REGEX_LEN:
                problems.append(f"{rule_id}: regex too long (>{MAX_REGEX_LEN})")'''
new_lint = '''        if op == "regex":
            if len(str(operand)) > MAX_REGEX_LEN:
                problems.append(f"{rule_id}: regex too long (>{MAX_REGEX_LEN})")
            if re.search(r"\\([^)]*[+*][^)]*\\)[+*]", str(operand)):
                problems.append(f"{rule_id}: nested quantifier in regex (ReDoS shape)")'''
if old_lint not in text:
    raise SystemExit("lint anchor not found")
text = text.replace(old_lint, new_lint, 1)

io.open(PATH, "w", encoding="utf-8", newline="\\n".replace("\\\\", "\\")).write(text)
print("MAX_REGEX_INPUT:", "MAX_REGEX_INPUT = 512" in text)
print("truncation:", text.count("[:MAX_REGEX_INPUT]"))
print("regex lint:", "nested quantifier" in text)
