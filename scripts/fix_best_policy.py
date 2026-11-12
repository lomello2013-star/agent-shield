"""F10: the 'best' policy must exclude the risky user-writable variant."""

import io

PATH = "scripts/stage2_measure.py"
text = io.open(PATH, encoding="utf-8").read()

old = '''    best = min(report["holdout"]["policies"].items(),
               key=lambda kv: kv[1]["false_block"]["false_block_rate_pct"])
    report["holdout"]["best"] = {"policy": best[0],
                                 "false_block_pct": best[1]["false_block"]["false_block_rate_pct"],
                                 "target_pct": 10.0,
                                 "within_target": best[1]["false_block"]["false_block_rate_pct"] <= 10.0}'''
new = '''    risky = set(report["holdout"]["risky_variants"])
    sound = {k: v for k, v in report["holdout"]["policies"].items() if k not in risky}
    best = min(sound.items(), key=lambda kv: kv[1]["false_block"]["false_block_rate_pct"])
    report["holdout"]["best"] = {
        "policy": best[0],
        "false_block_pct": best[1]["false_block"]["false_block_rate_pct"],
        "coverage_pct": best[1]["coverage"]["coverage_pct"],
        "target_pct": 10.0,
        "target_fbr_met": best[1]["false_block"]["false_block_rate_pct"] <= 10.0,
        "coverage_target_pct": 99.5,
        "coverage_met": best[1]["coverage"]["coverage_pct"] >= 99.5,
        "risky_alternative": {
            "policy": "J_allow_user_writable_risk",
            "false_block_pct": report["holdout"]["policies"]["J_allow_user_writable_risk"][
                "false_block"]["false_block_rate_pct"],
            "rejected_because": "allowing user-writable AppData defeats default-deny; a "
                                "0 % false-block rate achieved this way is not a policy win",
        },
        "conclusion": "on unseen inventory a sound policy floors at ~13 % FBR; the target "
                      "needs a hash/update feed (pilot) rather than path widening",
    }'''
if old not in text:
    raise SystemExit("best anchor not found")
text = text.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("best now excludes risky variants")
