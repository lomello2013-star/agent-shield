"""Fix ordering: risky_variants must be added after report["holdout"] is created."""

import io

PATH = "scripts/stage2_measure.py"
text = io.open(PATH, encoding="utf-8").read()

block = '''    # What it would cost to reach the FBR target: allowing user-writable directories
    # (AppData) defeats default-deny, so it is measured explicitly as a risky variant.
    user_writable = [p for p in (os.environ.get("LOCALAPPDATA", r"C:\\Users\\x\\AppData\\Local"),
                                 os.environ.get("APPDATA", r"C:\\Users\\x\\AppData\\Roaming")) if p]
    holdout_variants["J_allow_user_writable_risk"] = AllowlistEvaluator(
        signed_any=True, paths=program_paths + [p + "\\\\" for p in user_writable])
    report["holdout"]["risky_variants"] = {
        "J_allow_user_writable_risk": {
            "note": "allows user-writable AppData: low FBR but defeats default-deny",
            "paths": [p + "\\\\" for p in user_writable],
        }
    }
'''
if block not in text:
    raise SystemExit("block not found")

text = text.replace(block, '''    # What it would cost to reach the FBR target: allowing user-writable directories
    # (AppData) defeats default-deny, so it is measured explicitly as a risky variant.
    user_writable = [p for p in (os.environ.get("LOCALAPPDATA", r"C:\\Users\\x\\AppData\\Local"),
                                 os.environ.get("APPDATA", r"C:\\Users\\x\\AppData\\Roaming")) if p]
    holdout_variants["J_allow_user_writable_risk"] = AllowlistEvaluator(
        signed_any=True, paths=program_paths + [p + "\\\\" for p in user_writable])
''', 1)

anchor = '''    report["holdout"]["policies"] = {
        name: {"false_block": ev.false_block_rate(holdout),
               "coverage": ev.coverage(holdout)}
        for name, ev in holdout_variants.items()
    }'''
if anchor not in text:
    raise SystemExit("policies anchor not found")
text = text.replace(anchor, anchor + '''
    report["holdout"]["risky_variants"] = {
        "J_allow_user_writable_risk": {
            "note": "allows user-writable AppData: low FBR but defeats default-deny",
            "paths": [p + "\\\\" for p in user_writable],
        }
    }''', 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("reordered ok")
