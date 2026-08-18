#!/usr/bin/env python3
"""Collect proxy user traffic and report it to the VPN subscription admin.

Recommended Xray cron, every 5 minutes:
  python3 /opt/iguang-sub/scripts/xray_usage_collector.py \
    --backend xray \
    --xray-bin /usr/local/bin/xray \
    --xray-api 127.0.0.1:10085 \
    --reset \
    --report-url https://sub.0909106.xyz/api/traffic/report \
    --token YOUR_UPDATE_TOKEN

For non-reset Xray counters, use a state file to report deltas:
  python3 scripts/xray_usage_collector.py --backend xray --state-file /var/lib/iguang-sub/xray-traffic.json ...
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


XRAY_STAT_RE = re.compile(
    r'name:\s*"user>>>(?P<email>.+?)>>>traffic>>>(?P<direction>uplink|downlink)".*?value:\s*(?P<value>\d+)',
    re.S,
)


def parse_xray_stats(text: str) -> dict[str, dict[str, int]]:
    users: dict[str, dict[str, int]] = {}
    for match in XRAY_STAT_RE.finditer(text or ""):
        email = match.group("email").strip()
        if not email:
            continue
        direction = match.group("direction")
        value = int(match.group("value"))
        item = users.setdefault(email, {"upload": 0, "download": 0})
        if direction == "uplink":
            item["upload"] += value
        else:
            item["download"] += value
    return users


def query_xray(xray_bin: str, xray_api: str, reset: bool) -> str:
    cmd = [
        xray_bin,
        "api",
        "statsquery",
        f"--server={xray_api}",
        "-pattern",
        "user>>>",
    ]
    if reset:
        cmd.append("-reset")
    return subprocess.check_output(cmd, text=True, encoding="utf-8", errors="replace")


def load_state(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(path: str, payload: dict[str, Any]) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp_name, target)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def build_xray_report(
    counters: dict[str, dict[str, int]],
    *,
    reset: bool,
    state_file: str,
    report_first_snapshot: bool,
) -> list[dict[str, Any]]:
    previous = load_state(state_file).get("users", {}) if state_file else {}
    users: list[dict[str, Any]] = []

    for traffic_key, values in sorted(counters.items()):
        upload = int(values.get("upload") or 0)
        download = int(values.get("download") or 0)
        total = upload + download
        prev = previous.get(traffic_key) or {}
        prev_total = int(prev.get("upload") or 0) + int(prev.get("download") or 0)

        if reset:
            delta_upload = upload
            delta_download = download
            mode = "delta"
        elif state_file:
            delta_upload = max(0, upload - int(prev.get("upload") or 0))
            delta_download = max(0, download - int(prev.get("download") or 0))
            mode = "delta"
            if not prev and not report_first_snapshot:
                delta_upload = 0
                delta_download = 0
        else:
            delta_upload = upload
            delta_download = download
            mode = "absolute"

        if mode == "delta":
            delta = delta_upload + delta_download
            if delta <= 0:
                continue
            users.append(
                {
                    "traffic_key": traffic_key,
                    "upload": delta_upload,
                    "download": delta_download,
                    "delta_bytes": delta,
                    "mode": "delta",
                    "protocol": "xray",
                    "action": "流量增量",
                    "message": "Xray stats reset" if reset else f"Xray stats delta from {prev_total} to {total}",
                }
            )
        else:
            users.append(
                {
                    "traffic_key": traffic_key,
                    "upload": upload,
                    "download": download,
                    "used_bytes": total,
                    "mode": "absolute",
                    "protocol": "xray",
                    "action": "流量快照",
                    "message": "Xray stats absolute snapshot",
                }
            )

    if state_file:
        save_state(state_file, {"users": counters})
    return users


def fetch_json(url: str, timeout: int = 10) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def connection_user(connection: dict[str, Any]) -> str:
    metadata = connection.get("metadata") or {}
    candidates = [
        connection.get("traffic_key"),
        connection.get("user"),
        connection.get("email"),
        connection.get("inboundUser"),
        metadata.get("user"),
        metadata.get("email"),
        metadata.get("inboundUser"),
        metadata.get("authUser"),
    ]
    for value in candidates:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def build_sing_box_report(api_url: str, include_unmatched: bool = False) -> list[dict[str, Any]]:
    payload = fetch_json(api_url.rstrip("/") + "/connections")
    connections = payload.get("connections") if isinstance(payload, dict) else []
    users: dict[str, dict[str, Any]] = {}
    unmatched = 0
    for conn in connections or []:
        if not isinstance(conn, dict):
            continue
        traffic_key = connection_user(conn)
        if not traffic_key:
            unmatched += 1
            if not include_unmatched:
                continue
            traffic_key = "(unmatched)"
        item = users.setdefault(
            traffic_key,
            {
                "traffic_key": traffic_key,
                "upload": 0,
                "download": 0,
                "connections": 0,
                "protocol": "sing-box",
                "node": "",
                "source_ip": "",
                "mode": "event",
                "action": "连接采样",
            },
        )
        item["upload"] += int(conn.get("upload") or conn.get("uplink") or 0)
        item["download"] += int(conn.get("download") or conn.get("downlink") or 0)
        item["connections"] += 1
        metadata = conn.get("metadata") or {}
        item["node"] = item["node"] or str(conn.get("chains") or conn.get("rule") or "")
        item["source_ip"] = item["source_ip"] or str(metadata.get("sourceIP") or metadata.get("source_ip") or "")

    report = list(users.values())
    if unmatched and not include_unmatched:
        print(f"sing-box: skipped {unmatched} connections without user metadata", file=sys.stderr)
    return report


def post_report(report_url: str, token: str, users: list[dict[str, Any]], dry_run: bool = False) -> str:
    payload = json.dumps({"users": users}, ensure_ascii=False).encode("utf-8")
    if dry_run:
        return payload.decode("utf-8")
    req = urllib.request.Request(
        report_url,
        data=payload,
        headers={"Content-Type": "application/json", "X-Update-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["xray", "sing-box"], default="xray")
    parser.add_argument("--xray-bin", default="xray")
    parser.add_argument("--xray-api", default="127.0.0.1:10085")
    parser.add_argument("--sing-box-api", default="http://127.0.0.1:9090")
    parser.add_argument("--report-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--reset", action="store_true", help="Reset Xray counters after reading and report as delta.")
    parser.add_argument("--state-file", default="", help="Store previous absolute counters and report deltas.")
    parser.add_argument("--report-first-snapshot", action="store_true", help="When using --state-file, report first snapshot as delta.")
    parser.add_argument("--include-unmatched", action="store_true", help="For sing-box connection sampling, report connections without user metadata.")
    parser.add_argument("--sample-file", help="Parse a saved Xray statsquery output instead of calling xray.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.backend == "xray":
        if args.sample_file:
            with open(args.sample_file, "r", encoding="utf-8") as f:
                raw = f.read()
        else:
            raw = query_xray(args.xray_bin, args.xray_api, args.reset)
        users = build_xray_report(
            parse_xray_stats(raw),
            reset=args.reset,
            state_file=args.state_file,
            report_first_snapshot=args.report_first_snapshot,
        )
    else:
        users = build_sing_box_report(args.sing_box_api, include_unmatched=args.include_unmatched)

    if not users:
        print(json.dumps({"status": "empty", "users": 0}, ensure_ascii=False))
        return 0
    print(post_report(args.report_url, args.token, users, dry_run=args.dry_run))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
