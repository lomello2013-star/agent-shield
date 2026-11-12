"""Make the F08 experiment crash-resistant: smaller configs + progress output."""

import io

PATH = "scripts/f08_tail_search.py"
text = io.open(PATH, encoding="utf-8").read()

text = text.replace(
    'deeper_params = dict(base_params, num_leaves=128, learning_rate=0.03)',
    'deeper_params = dict(base_params, num_leaves=112, learning_rate=0.04)')
text = text.replace('deeper = train("B_deeper", Xtr, ytr, deeper_params, 1500)',
                    'deeper = train("B_deeper", Xtr, ytr, deeper_params, 1000)')

# progress output so a crash still leaves evidence
text = text.replace(
    '    report["runs"].append({"name": "A_baseline", "train_s": baseline["train_s"],\n'
    '                           "auc": round(float(roc_auc_score(yte, scores_a)), 5),\n'
    '                           **evaluate(scores_a, yte)})',
    '    report["runs"].append({"name": "A_baseline", "train_s": baseline["train_s"],\n'
    '                           "auc": round(float(roc_auc_score(yte, scores_a)), 5),\n'
    '                           **evaluate(scores_a, yte)})\n'
    '    print("A:", report["runs"][-1]["tpr_at_fpr_0.0005"], flush=True)')
text = text.replace(
    '    report["runs"].append({"name": "B_deeper", "train_s": deeper["train_s"],\n'
    '                           "auc": round(float(roc_auc_score(yte, scores_b)), 5),\n'
    '                           **evaluate(scores_b, yte)})',
    '    report["runs"].append({"name": "B_deeper", "train_s": deeper["train_s"],\n'
    '                           "auc": round(float(roc_auc_score(yte, scores_b)), 5),\n'
    '                           **evaluate(scores_b, yte)})\n'
    '    print("B:", report["runs"][-1]["tpr_at_fpr_0.0005"], flush=True)')
text = text.replace(
    '    report["runs"].append({"name": "C_hard_negative", "train_s": mined["train_s"],\n'
    '                           "hard_rows_added": int(len(hard_mask)),\n'
    '                           "auc": round(float(roc_auc_score(yte, scores_c)), 5),\n'
    '                           **evaluate(scores_c, yte)})',
    '    report["runs"].append({"name": "C_hard_negative", "train_s": mined["train_s"],\n'
    '                           "hard_rows_added": int(len(hard_mask)),\n'
    '                           "auc": round(float(roc_auc_score(yte, scores_c)), 5),\n'
    '                           **evaluate(scores_c, yte)})\n'
    '    print("C:", report["runs"][-1]["tpr_at_fpr_0.0005"], flush=True)')

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("progress prints:", text.count("flush=True"))
print("deeper 1000 trees:", "deeper_params, 1000" in text)
