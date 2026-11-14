"""`stmlctl` — project-specific operator CLI (no arbitrary shell)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_URL = os.environ.get("STML_URL", "http://127.0.0.1:8080")


class CliError(RuntimeError):
    pass


def _tokens(args: argparse.Namespace) -> dict[str, str]:
    out = {
        "viewer": os.environ.get("STML_VIEWER_TOKEN", ""),
        "admin": os.environ.get("STML_ADMIN_TOKEN", ""),
        "approver": os.environ.get("STML_APPROVER_TOKEN", ""),
    }
    path = args.tokens_file or os.environ.get("STML_TOKENS_FILE", "")
    if path and Path(path).exists():
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            for role in out:
                out[role] = out[role] or str(data.get(f"{role}_token", ""))
        except (OSError, json.JSONDecodeError) as exc:
            raise CliError(f"cannot read tokens file: {exc}") from exc
    return out


def _request(args: argparse.Namespace, method: str, path: str,
             payload: Any = None, role: str | None = None) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if role:
        token = _tokens(args).get(role, "")
        if not token:
            raise CliError(f"{role} token not configured (env or --tokens-file)")
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(args.url.rstrip("/") + path, data=data,
                                     method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as resp:
            body = resp.read().decode()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            detail = json.loads(body).get("error", body)
        except json.JSONDecodeError:
            detail = body
        raise CliError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CliError(f"cannot reach {args.url}: {exc.reason}") from exc


def _print(args: argparse.Namespace, payload: Any, human: str) -> None:
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(human)


def _agents(args):
    data = _request(args, "GET", "/v0/agents", role="viewer")
    rows = data.get("agents", [])
    lines = ["HOST\tSTATUS\tVERSION\tPOLICY\tISOLATED"]
    for a in rows:
        lines.append(f"{a.get('hostname','')}\t{a.get('status','')}\t"
                     f"{a.get('agent_version','')}\t{a.get('policy_version') or '-'}\t"
                     f"{'yes' if a.get('isolated') else 'no'}")
    _print(args, data, "\n".join(lines))


def _policies(args):
    data = _request(args, "GET", "/v0/policies", role="viewer")
    rows = data.get("policies", [])
    lines = ["POLICY\tVERSION\tCHANNEL\tKEY"]
    for p in rows:
        lines.append(f"{p.get('policy_id','')}\t{p.get('version','')}\t"
                     f"{p.get('channel','')}\t{p.get('key_id','')}")
    _print(args, data, "\n".join(lines))


def _apply_policy(args):
    path = Path(args.file)
    if not path.exists():
        raise CliError(f"policy file not found: {path}")
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CliError(f"bad policy JSON: {exc}") from exc
    data = _request(args, "POST", "/v0/policies", policy, role="admin")
    _print(args, data, json.dumps(data, ensure_ascii=False))


def _approvals(args):
    data = _request(args, "GET", "/v0/approvals", role="viewer")
    rows = data.get("approvals", [])
    lines = ["ID\tKIND\tTARGET\tSTATUS\tDECIDED"]
    for a in rows:
        lines.append(f"{a.get('id','')}\t{a.get('kind','')}\t{a.get('target','')}\t"
                     f"{a.get('status','')}\t{a.get('decided_by') or '-'}")
    _print(args, data, "\n".join(lines))


def _decide(args):
    action = "approve" if args.command == "approve" else "deny"
    data = _request(args, "POST", f"/v0/approvals/{args.id}/{action}", {},
                    role="approver")
    _print(args, data, json.dumps(data, ensure_ascii=False))


def _isolate(args):
    data = _request(args, "POST", f"/v0/agents/{args.agent_id}/isolate",
                    {"isolated": not args.resume}, role="admin")
    _print(args, data, json.dumps(data, ensure_ascii=False))


def _commands(args):
    data = _request(args, "GET", f"/v0/agents/{args.agent_id}/commands", role="viewer")
    rows = data.get("commands", [])
    lines = ["KIND\tSTATUS\tCREATED"]
    for c in rows:
        lines.append(f"{c.get('kind','')}\t{c.get('status','')}\t{c.get('created_at','')}")
    _print(args, data, "\n".join(lines))


def _rollout_start(args):
    data = _request(args, "POST", "/v0/rollouts",
                    {"policy_id": args.policy_id, "version": args.version,
                     "percent": args.percent}, role="admin")
    _print(args, data, json.dumps(data, ensure_ascii=False))


def _rollout_action(args):
    data = _request(args, "POST", f"/v0/rollouts/{args.rollout_id}/{args.command}",
                    {}, role="admin")
    _print(args, data, json.dumps(data, ensure_ascii=False))


def _audit(args):
    data = _request(args, "GET", "/v0/audit/verify", role="admin")
    _print(args, data, f"audit_ok={data.get('ok')}")


def _health(args):
    data = _request(args, "GET", "/health")
    _print(args, data, json.dumps(data, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="stmlctl",
                                description="STML operator CLI (allowlisted commands only)")
    p.add_argument("--url", default=DEFAULT_URL, help="STML base URL")
    p.add_argument("--tokens-file", default=os.environ.get("STML_TOKENS_FILE", ""),
                   help="JSON with viewer_token/admin_token/approver_token")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true", help="raw JSON output")
    sub = p.add_subparsers(dest="group", required=True)

    fleet = sub.add_parser("fleet", help="fleet listing")
    fleet_sub = fleet.add_subparsers(dest="command", required=True)
    fleet_sub.add_parser("list", help="list agents").set_defaults(func=_agents)
    fleet_sub.add_parser("ls", help="list agents").set_defaults(func=_agents)

    pol = sub.add_parser("policy", help="policies")
    pol_sub = pol.add_subparsers(dest="command", required=True)
    pol_sub.add_parser("list", help="list policies").set_defaults(func=_policies)
    apply_p = pol_sub.add_parser("apply", help="apply signed policy JSON")
    apply_p.add_argument("file")
    apply_p.set_defaults(func=_apply_policy)

    appr = sub.add_parser("approvals", help="approval queue")
    appr_sub = appr.add_subparsers(dest="command", required=True)
    appr_sub.add_parser("list", help="list approvals").set_defaults(func=_approvals)
    appr_sub.add_parser("ls", help="list approvals").set_defaults(func=_approvals)

    for name in ("approve", "deny"):
        cmd = sub.add_parser(name, help=f"{name} an approval")
        cmd.add_argument("id", type=int)
        cmd.set_defaults(func=_decide)

    iso = sub.add_parser("isolate", help="isolate or resume an agent")
    iso.add_argument("agent_id")
    iso.add_argument("--resume", action="store_true")
    iso.set_defaults(func=_isolate)

    cmds = sub.add_parser("commands", help="show agent command queue")
    cmds.add_argument("agent_id")
    cmds.set_defaults(func=_commands)

    roll = sub.add_parser("rollout", help="rollouts")
    roll_sub = roll.add_subparsers(dest="command", required=True)
    start = roll_sub.add_parser("start")
    start.add_argument("policy_id")
    start.add_argument("version")
    start.add_argument("--percent", type=int, default=1)
    start.set_defaults(func=_rollout_start)
    for action in ("promote", "halt", "rollback"):
        cmd = roll_sub.add_parser(action)
        cmd.add_argument("rollout_id", type=int)
        cmd.set_defaults(func=_rollout_action)

    audit = sub.add_parser("audit", help="audit")
    audit_sub = audit.add_subparsers(dest="command", required=True)
    audit_sub.add_parser("verify").set_defaults(func=_audit)

    sub.add_parser("health", help="server health").set_defaults(func=_health)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except CliError as exc:
        print(f"stmlctl: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
