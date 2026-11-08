#!/usr/bin/env python3
"""Luna cutover observation only. Never reads credentials or changes network policy.
A successful observation is NOT authorization to execute a ban.
"""
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import sqlite3
import subprocess

ROOT = Path("/home/ubuntu/services")
BASE = ROOT / "sentinel-site-guardian"
OUT = BASE / "reports" / "cutover"
OUT.mkdir(parents=True, exist_ok=True)

def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}

def iso_age_minutes(value, now):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return round((now - dt.astimezone(timezone.utc)).total_seconds() / 60, 1)
    except (ValueError, TypeError):
        return None

def unit_state(unit):
    try:
        x = subprocess.run(["systemctl", "is-enabled", unit],
                           capture_output=True, text=True, timeout=3)
        return x.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"

def queue_state(db):
    try:
        con = sqlite3.connect("file:" + str(db) + "?mode=ro", uri=True, timeout=3)
        con.execute("PRAGMA query_only=ON")
        value = con.execute("SELECT COUNT(*) FROM alert_outbox WHERE delivered_at IS NULL").fetchone()[0]
        con.close()
        return int(value)
    except (sqlite3.Error, OSError):
        return None

def atomic_json(path, payload):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    os.chmod(temp, 0o600)
    temp.replace(path)

def main():
    now = datetime.now(timezone.utc)
    policy = read_json(BASE / "owner_assignments.json")
    cycle = read_json(BASE / "reports/cycle_status.json")
    decisions = read_json(BASE / "reports/decisions_latest.json")
    guardian = read_json(BASE / "reports/latest.json")
    luna_guard = read_json(ROOT / "micro-sentinel/reports/guard/latest.json")
    luna_behavior = read_json(ROOT / "micro-sentinel/reports/behavioral/latest.json")
    luna_db = ROOT / "micro-sentinel/state/sentinel.db"
    removed_collector = ROOT / "micro-sentinel-b"
    fs = os.statvfs("/home")
    disk_used = round(100 * (1 - fs.f_bavail / fs.f_blocks), 1) if fs.f_blocks else None
    paths = {name: obj.get("agent_directory") for name, obj in policy.get("agents", {}).items()}
    observed_sites = {name: {"host": item.get("host"), "decision": item.get("decision"),
                             "executed": item.get("decision_executed")}
                      for name, item in cycle.get("site_guardians", {}).items()}
    report = {
        "schema": "SENTINEL_SINGLE_COLLECTOR_OBSERVE_72H_V1",
        "observed_utc": now.isoformat(),
        "collector": "Luna",
        "per_site_profiles": observed_sites,
        "primary_timer": unit_state("micro-sentinel.timer"),
        "retired_timer": "removed" if not Path("/etc/systemd/system/micro-sentinel-b.timer").exists() else unit_state("micro-sentinel-b.timer"),
        "single_source": len(paths) == 2 and len(set(paths.values())) == 1
                         and all(p == str(ROOT / "micro-sentinel") for p in paths.values()),
        "policy_shadow_only": policy.get("enforcement_enabled") is False
                         and policy.get("enforcement_backend") is None,
        "cycle_age_minutes": iso_age_minutes(cycle.get("time_utc"), now),
        "guardian_age_minutes": iso_age_minutes(guardian.get("generated_at_utc"), now),
        "guardian_guard_pass": luna_guard.get("state") == "PASS"
                               and luna_guard.get("violations") == [],
        "behavioral_pass": luna_behavior.get("state") == "PASS",
        "actual_bans": decisions.get("actual_bans"),
        "reported_fail2ban_actions": cycle.get("fail2ban_actions"),
        "site_decision_executions": {k: v.get("executed") for k, v in decisions.get("agents", {}).items()},
        "luna_outbox_pending": queue_state(luna_db),
        "duplicate_collector_present": removed_collector.exists(),
        "disk_percent_used": disk_used,
        "disk_bytes_available": fs.f_bavail * fs.f_frsize,
        "external_telegram_receipt": "UNVERIFIED",
        "automatic_ban_approval": "NOT_GRANTED",
        "unmet_live_gates": [
            "Trusted original client IP unverified at ingress",
            "Site-scoped enforcement backend unimplemented",
            "Independent 72h false-positive and application-health acceptance pending",
            "Owner live-action release not granted"
        ],
    }
    freshness = all(isinstance(report[k], (float, int))
                    and -2 <= report[k] <= 10 for k in ("cycle_age_minutes", "guardian_age_minutes"))
    zero_actions = report["actual_bans"] == 0 and report["reported_fail2ban_actions"] == 0
    correct_profiles = set(observed_sites) == {"Luna", "Luna:LightRemote"} and all(
        item.get("executed") is False for item in observed_sites.values())
    outbox_ok = isinstance(report["luna_outbox_pending"], int) and report["luna_outbox_pending"] <= 100
    disk_ok = disk_used is not None and disk_used < 92
    report["observation_state"] = (
        "PASS_OBSERVE_ONLY" if all((freshness, zero_actions, correct_profiles,
            outbox_ok, disk_ok, report["primary_timer"] == "enabled",
            report["retired_timer"] in ("disabled","removed"), not report["duplicate_collector_present"], report["single_source"],
            report["policy_shadow_only"], report["guardian_guard_pass"],
            report["behavioral_pass"])) else "NEEDS_REVIEW"
    )
    report["can_auto_enable_enforcement"] = False
    atomic_json(OUT / "latest.json", report)
    with (OUT / "history.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n")
    print(json.dumps({k: report[k] for k in (
        "observed_utc", "observation_state", "primary_timer", "retired_timer",
        "single_source", "luna_outbox_pending", "disk_percent_used",
        "actual_bans", "can_auto_enable_enforcement")}, ensure_ascii=False))

if __name__ == "__main__":
    main()
