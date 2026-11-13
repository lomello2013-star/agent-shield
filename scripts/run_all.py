"""Single entry point: run the whole regression set and write docs/status.md.

Steps (fail-fast is not used: every step runs, failures are reported together):
  1. unit/contract tests (pytest);
  2. rule lint + ATT&CK coverage numbers;
  3. contract JSON-schema drift check;
  4. immutable-policy verification;
  5. artefact sanity (JSON files exist and parse);
  6. Windows e2e lanes: System log, Defender log, consolidated chaos;
  7. optional Linux lanes via WSL (exec / LSM / net), skipped if WSL is absent.

Outputs: artifacts/run_all.json and docs/status.md (both generated; do not hand-edit).
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

ART = os.path.join(HERE, "artifacts")
OUT_JSON = os.path.join(ART, "run_all.json")
STATUS_MD = os.path.join(HERE, "docs", "status.md")
PY = sys.executable


class Step:
    def __init__(self, name: str, required: bool = True):
        self.name = name
        self.required = required
        self.ok = False
        self.detail = ""
        self.duration_s = 0.0
        self.artifact = ""


def run_command(argv: list[str], cwd: str = HERE, timeout: int = 600,
                shell: bool = False, env_extra: dict[str, str] | None = None) -> tuple[int, str, str]:
    # UTF-8 with replacement: child output may be Cyrillic regardless of the console
    env = dict(os.environ, PYTHONIOENCODING="utf-8", **(env_extra or {}))
    completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=timeout, shell=shell, env=env)
    # Child stderr may contain NUL bytes (native-crash probes); strip them so the
    # generated status.md stays valid text (P0-6).
    return (completed.returncode,
            completed.stdout.replace("\x00", ""),
            completed.stderr.replace("\x00", ""))


def step_tests() -> Step:
    s = Step("tests")
    code, out, err = run_command([PY, "-m", "pytest"])   # pyproject adds -q once
    text = out or err
    summary_lines = [line for line in text.splitlines() if "passed" in line or "failed" in line]
    s.ok = code == 0
    s.detail = summary_lines[-1].strip() if summary_lines else " | ".join(text.strip().splitlines()[-2:])
    return s


def step_rules() -> Step:
    s = Step("rules_and_coverage")
    try:
        from core.coverage import build_matrix, load_techniques, summarize
        from core.rules import lint_rules, load_rules
        rules = load_rules([os.path.join(HERE, "rules", "base.json")])
        tech = load_techniques(os.path.join(HERE, "rules", "techniques.json"))
        problems = lint_rules(rules, known_techniques={t.id for t in tech})
        summary = summarize(build_matrix(tech, rules))
        s.ok = not problems
        s.detail = (f"rules={len(rules)} lint={len(problems)} "
                    f"detection={summary['detection_pct']}% "
                    f"prevention={summary['prevention_pct']}%")
    except Exception as exc:                     # a broken import is a failure, not a skip
        s.ok, s.detail = False, f"{type(exc).__name__}: {exc}"
    return s


def step_schema_drift() -> Step:
    s = Step("schema_drift")
    try:
        import tempfile

        from schemas.v3 import export_json_schemas
        tmp = tempfile.mkdtemp(prefix="aidf_schema_")
        export_json_schemas(tmp)
        committed = os.path.join(HERE, "schemas", "v3", "json_schema")
        drift = []
        for name in os.listdir(tmp):
            a, b = os.path.join(tmp, name), os.path.join(committed, name)
            if not os.path.exists(b):
                drift.append(name)
                continue
            with open(a, encoding="utf-8") as fa, open(b, encoding="utf-8") as fb:
                if json.load(fa) != json.load(fb):
                    drift.append(name)
        s.ok = not drift
        s.detail = "in sync" if not drift else f"drifted: {drift[:5]}"
    except Exception as exc:
        s.ok, s.detail = False, f"{type(exc).__name__}: {exc}"
    return s


def step_immutable() -> Step:
    s = Step("immutable_policy")
    try:
        from core.policy import POLICY_FINGERPRINT, load_contract, verify_immutable
        verify_immutable()                     # live vs docs/policy-contract.json
        contract = load_contract()
        if contract.get("fingerprint") != POLICY_FINGERPRINT:
            raise RuntimeError("fingerprint mismatch with docs/policy-contract.json")
        s.ok = True
        s.detail = f"fingerprint={POLICY_FINGERPRINT[:12]} contract=ok"
    except Exception as exc:
        s.ok, s.detail = False, str(exc)
    return s


def load_json_any(path: str):
    """Artifacts may be UTF-8 (Python) or UTF-16LE (PowerShell redirection)."""
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            with open(path, encoding=encoding) as fh:
                return json.load(fh)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f"unreadable json: {path}")


def step_artifacts() -> Step:
    s = Step("artifacts")
    required = ["stage1_report.json", "stage2_report.json", "stage4_report.json",
                "stage5_report.json", "stage7_report.json", "stage8_report.json",
                "stage11_report.json", "stage12_chaos.json", "chaos_report.json",
                "gate_report.json", "ipc_report.json", "linux_e2e.json",
                "linux_lsm.json", "linux_net.json", "windows_e2e.json",
                "windows_defender.json", "pe_v2_report.json", "ship_v2.json",
                "calibration_report.json", "challenger_report.json", "disagreement_report.json", "ensemble_report.json", "linux_mem.json", "linux_ptrace.json", "linux_procmem.json", "linux_mprotect.json", "t1055_coverage.json", "linux_corr.json", "linux_tree.json", "linux_tree_fp.json", "linux_provenance.json", "final_summary.json", "f04_r2_margin.json", "f02_f03_measure.json", "f01_confidence.json", "f09_ppv_target.json", "f12_behavioral.json", "f13_scenarios.json", "supervisor_measure.json"]
    missing, broken = [], []
    for name in required:
        path = os.path.join(ART, name)
        if not os.path.exists(path):
            missing.append(name)
            continue
        try:
            load_json_any(path)
        except (OSError, ValueError):
            broken.append(name)
    s.ok = not missing and not broken
    s.detail = f"present={len(required) - len(missing)}/{len(required)}" + (
        f" missing={missing}" if missing else "") + (f" broken={broken}" if broken else "")
    return s


ARTIFACT_OF = {
    "windows_e2e.py": "windows_e2e.json",
    "windows_defender_e2e.py": "windows_defender.json",
    "stage12_chaos.py": "stage12_chaos.json",
}


def tidy_artifacts() -> int:
    """F16: keep artifacts/ for measurements only; diagnostics go to artifacts/_stdout."""
    out_dir = os.path.join(ART, "_stdout")
    os.makedirs(out_dir, exist_ok=True)
    moved = 0
    for path in glob.glob(os.path.join(ART, "*")):
        if not os.path.isfile(path):
            continue
        base = os.path.basename(path)
        if "_stdout" in base or base.startswith("soak_partial"):
            try:
                os.replace(path, os.path.join(out_dir, base))
                moved += 1
            except OSError:
                pass          # file is open (e.g. the current shell redirect): leave it
    return moved


def step_script(name: str, script: str, required: bool = True,
                artifact: str | None = None) -> Step:
    s = Step(name, required=required)
    code, out, err = run_command([PY, os.path.join(HERE, "scripts", script)])
    s.ok = code == 0
    art_name = artifact or ARTIFACT_OF.get(script) or script.replace(".py", ".json")
    try:
        with open(os.path.join(ART, art_name), encoding="utf-8") as fh:
            data = json.load(fh)
        s.ok = s.ok and bool(data)
        if script == "windows_defender_e2e.py":
            s.detail = (f"events={data.get('events_read')} verdicts={data.get('verdicts')} "
                        f"before_classification={data.get('verdicts_before_classification')}")
        elif script == "windows_e2e.py":
            s.detail = f"events={data.get('events_read')} verdicts={data.get('verdicts')}"
        elif script == "stage12_chaos.py":
            s.detail = (f"final_verdicts={data.get('final', {}).get('verdicts')} "
                        f"loss={data.get('final', {}).get('lost')}")
        else:
            s.detail = f"exit={code} bytes={len(json.dumps(data))}"
    except Exception:
        s.detail = f"exit={code} (no json artefact read)"
    if err.strip():
        s.detail += f" stderr={err.strip().splitlines()[-1][:120]}"
    return s


def step_linux(name: str, script: str) -> Step:
    s = Step(name, required=False)
    if os.name != "nt":
        s.detail = "skipped (not Windows host)"
        return s
    try:
        wsl_path = subprocess.run(["wsl.exe", "-d", "Ubuntu", "-u", "root", "--",
                                   "wslpath", "-a", os.path.join(HERE, "scripts", script)],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=30)
        if wsl_path.returncode != 0:
            s.detail = "skipped (WSL unavailable)"
            return s
        code, out, err = run_command(["wsl.exe", "-d", "Ubuntu", "-u", "root", "--",
                                      "bash", wsl_path.stdout.strip()], timeout=600)
        s.ok = code == 0
        s.detail = f"exit={code}" + (f" stderr={err.strip().splitlines()[-1][:120]}"
                                     if err.strip() else "")
    except Exception as exc:
        s.detail = f"skipped ({type(exc).__name__})"
    return s


def step_soak(seconds: int) -> Step:
    """Optional long run: the only way to approach R1/R4 (availability/sessions)."""
    s = Step("soak", required=False)
    code, out, err = run_command([PY, os.path.join(HERE, "scripts", "soak_daemon.py")],
                                 timeout=seconds + 300,
                                 env_extra={"AIDF_SOAK_SECONDS": str(seconds)})
    s.ok = code == 0
    try:
        data = load_json_any(os.path.join(ART, "soak_report.json"))
        load = data.get("load", {})
        final = data.get("final", {})
        memory = data.get("memory", {})
        s.detail = (f"{seconds}s events={load.get('events_fed')} lost={final.get('lost')} "
                    f"rss+{memory.get('growth_pct')}% "
                    f"last60s={data.get('rss_growth_last_60s_pct')}% "
                    f"plateau={data.get('rss_plateau')}")
    except Exception as exc:
        s.detail = f"exit={code} ({type(exc).__name__})"
    return s


def write_status(steps: list[Step], artifacts: dict[str, dict],
                 run_started_ts: float | None = None) -> None:
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    import status_text
    content = status_text.render(steps, artifacts, datetime.now(timezone.utc), ART,
                                 run_started_ts)
    os.makedirs(os.path.dirname(STATUS_MD), exist_ok=True)
    with open(STATUS_MD, "w", encoding="utf-8") as fh:
        fh.write(content)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Full regression run for AIDefender")
    parser.add_argument("--with-soak", action="store_true",
                        help="also run the soak harness (minutes; optional, not required)")
    parser.add_argument("--soak-seconds", type=int, default=180,
                        help="soak duration when --with-soak is used")
    args = parser.parse_args()

    os.makedirs(ART, exist_ok=True)
    tidy_artifacts()
    steps: list[Step] = []
    t_all = time.perf_counter()
    started_wall = datetime.now(timezone.utc).timestamp()
    for fn in (step_tests, step_rules, step_schema_drift, step_immutable, step_artifacts):
        t0 = time.perf_counter()
        step = fn()
        step.duration_s = round(time.perf_counter() - t0, 2)
        steps.append(step)
    for name, script in (("windows_system_e2e", "windows_e2e.py"),
                         ("windows_defender_e2e", "windows_defender_e2e.py"),
                         ("windows_chaos", "stage12_chaos.py")):
        t0 = time.perf_counter()
        step = step_script(name, script)
        step.duration_s = round(time.perf_counter() - t0, 2)
        steps.append(step)
    for name, script in (("linux_exec_e2e", "run_linux_e2e.sh"),
                         ("linux_lsm_e2e", "run_linux_lsm.sh"),
                         ("linux_net_e2e", "run_linux_net.sh"),
                         ("linux_mem_e2e", "run_linux_mem.sh"),
                         ("linux_ptrace_e2e", "run_linux_ptrace.sh"),
                         ("linux_procmem_e2e", "run_linux_procmem.sh"),
                         ("linux_mprotect_e2e", "run_linux_mprotect.sh"),
                         ("linux_corr_e2e", "run_linux_corr.sh"),
                         ("linux_tree_e2e", "run_linux_tree.sh"),
                         ("linux_tree_fp", "run_linux_tree_fp.sh"),
                         ("linux_provenance", "run_linux_provenance.sh")):
        t0 = time.perf_counter()
        step = step_linux(name, script)
        step.duration_s = round(time.perf_counter() - t0, 2)
        steps.append(step)

    t0 = time.perf_counter()
    env_backup = os.environ.get("AIDF_DEFER_CONSISTENCY")
    os.environ["AIDF_DEFER_CONSISTENCY"] = "1"
    try:
        step = step_script("gen_docs", "gen_docs.py")
    finally:
        if env_backup is None:
            os.environ.pop("AIDF_DEFER_CONSISTENCY", None)
        else:
            os.environ["AIDF_DEFER_CONSISTENCY"] = env_backup
    step.duration_s = round(time.perf_counter() - t0, 2)
    steps.append(step)

    for name, script in (("f04_r2_margin", "f04_measure.py"),
                         ("f02_f03_signal_levels", "f02_f03_measure.py"),
                         ("f01_confidence_gap", "f01_ppv_fit.py"),
                         ("f09_ppv_target", "f09_ppv_target.py"),
                         ("f12_behavioral", "f12_behavioral.py"),
                         ("f13_scenarios", "f13_scenarios.py"),
                         ("supervisor_measure", "supervisor_measure.py")):
        t0 = time.perf_counter()
        step = step_script(name, script)
        step.duration_s = round(time.perf_counter() - t0, 2)
        steps.append(step)

    t0 = time.perf_counter()
    step = step_script("final_summary", "final_summary.py")
    step.duration_s = round(time.perf_counter() - t0, 2)
    steps.append(step)

    if args.with_soak:
        t0 = time.perf_counter()
        step = step_soak(args.soak_seconds)
        step.duration_s = round(time.perf_counter() - t0, 2)
        steps.append(step)
    artifacts: dict[str, dict] = {}
    for path in glob.glob(os.path.join(ART, "*.json")):
        try:
            artifacts[os.path.basename(path)] = load_json_any(path)
        except (OSError, ValueError):
            continue

    # The status document must exist before consistency can be checked, so it is
    # written twice: once with the measurement steps, then again with the check step.
    write_status(steps, artifacts, started_wall)
    t0 = time.perf_counter()
    step = step_script("docs_consistency", "docs_consistency.py")
    step.duration_s = round(time.perf_counter() - t0, 2)
    steps.append(step)
    write_status(steps, artifacts, started_wall)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "steps": [{"name": s.name, "ok": s.ok, "required": s.required,
                   "detail": s.detail, "duration_s": s.duration_s} for s in steps],
        "passed": sum(1 for s in steps if s.ok),
        "failed_required": [s.name for s in steps if s.required and not s.ok],
        "total_s": round(time.perf_counter() - t_all, 2),
        "status_doc": STATUS_MD,
    }
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 1 if summary["failed_required"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

























