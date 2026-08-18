#!/usr/bin/env python3
"""VPN subscription aggregator with a small admin UI."""

from __future__ import annotations

import base64
import csv
import functools
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urlparse
from urllib.request import Request, urlopen

import qrcode
import qrcode.image.svg
import yaml
from flask import Flask, Response, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data" if Path("/data").exists() else APP_DIR / "data"))
NODES_FILE = Path(os.environ.get("NODES_FILE", DATA_DIR / "nodes.txt"))
DB_FILE = Path(os.environ.get("DB_FILE", DATA_DIR / "sub.db"))
BACKUP_DIR = DATA_DIR / "backups"
APP_VERSION = os.environ.get("APP_VERSION", "v2.9.1")
DINGYUE_SUBSCRIBER_NAME = os.environ.get("DINGYUE_SUBSCRIBER_NAME", "admin").strip() or "admin"
DINGYUE_PATH = "/" + (os.environ.get("DINGYUE_PATH", "dingyue").strip().strip("/") or "dingyue")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or os.environ.get("UPDATE_TOKEN") or "admin"
UPDATE_TOKEN = os.environ.get("UPDATE_TOKEN", ADMIN_PASSWORD)
PROFILE_TITLE = os.environ.get("PROFILE_TITLE", "RAY-VPN-Sub")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
SUB_TOKEN = os.environ.get("SUB_TOKEN", "").strip()
RETURN_TEST_HOST = os.environ.get("RETURN_TEST_HOST", "").strip()
RETURN_TEST_PORT = os.environ.get("RETURN_TEST_PORT", "443").strip()
UPSTREAM_USER_AGENT = os.environ.get("UPSTREAM_USER_AGENT", "ClashMetaForAndroid/2.11.13").strip()
GEO_LOOKUP_PROVIDER = os.environ.get("GEO_LOOKUP_PROVIDER", "ip-api").strip().lower()
GEO_CACHE_TTL_HOURS = int(os.environ.get("GEO_CACHE_TTL_HOURS", "168") or 168)
GEO_REFRESH_LIMIT = int(os.environ.get("GEO_REFRESH_LIMIT", "50") or 50)
EXPORT_MAX_ROWS = int(os.environ.get("EXPORT_MAX_ROWS", "50000") or 50000)
NODE_MONITOR_RETENTION_DAYS = int(os.environ.get("NODE_MONITOR_RETENTION_DAYS", "7") or 7)
NODE_MONITOR_MAX_PER_ASSET = int(os.environ.get("NODE_MONITOR_MAX_PER_ASSET", "2880") or 2880)
NODE_MONITOR_STALE_MINUTES = int(os.environ.get("NODE_MONITOR_STALE_MINUTES", "15") or 15)
FILTER_FAILED_UPSTREAM_NODES = os.environ.get("FILTER_FAILED_UPSTREAM_NODES", "0").strip().lower() not in {"0", "false", "no", "off"}
UPSTREAM_REQUIRE_PROXY_OK = os.environ.get("UPSTREAM_REQUIRE_PROXY_OK", "0").strip().lower() not in {"0", "false", "no", "off"}
SING_BOX_PATH = os.environ.get("SING_BOX_PATH", "/usr/local/bin/sing-box").strip()
PROXY_TEST_URLS = [item.strip() for item in os.environ.get("PROXY_TEST_URLS", "https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204").split(",") if item.strip()]
PROXY_TEST_LIMIT = int(os.environ.get("PROXY_TEST_LIMIT", "50") or 50)
SUBS_CHECK_BASE_URL = os.environ.get("SUBS_CHECK_BASE_URL", "http://subs-check:8199").rstrip("/")
SUBS_CHECK_PUBLIC_URL = os.environ.get("SUBS_CHECK_PUBLIC_URL", "http://127.0.0.1:18199").rstrip("/")
SUBS_CHECK_OUTPUT_PATH = os.environ.get("SUBS_CHECK_OUTPUT_PATH", "/all.yaml").strip() or "/all.yaml"
SUBS_CHECK_SUBSCRIPTION_ENABLED = os.environ.get("SUBS_CHECK_SUBSCRIPTION_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
SUBSCRIPTION_ENGINE_MODE = os.environ.get("SUBSCRIPTION_ENGINE_MODE", "balanced").strip().lower()
SUBS_CHECK_MIN_OUTPUT_NODES = int(os.environ.get("SUBS_CHECK_MIN_OUTPUT_NODES", "20") or 20)
SUBS_CHECK_CLASH_PATH = os.environ.get("SUBS_CHECK_CLASH_PATH", SUBS_CHECK_OUTPUT_PATH or "/all.yaml").strip() or "/all.yaml"
SUBS_CHECK_V2RAY_PATH = os.environ.get("SUBS_CHECK_V2RAY_PATH", "/base64.txt").strip() or "/base64.txt"
SUBS_CHECK_SURGE_PATH = os.environ.get("SUBS_CHECK_SURGE_PATH", "").strip()
SUBS_CHECK_QX_PATH = os.environ.get("SUBS_CHECK_QX_PATH", "").strip()
SUBS_CHECK_IMPORT_NAME = os.environ.get("SUBS_CHECK_IMPORT_NAME", "subs-check 已验真输出").strip() or "subs-check 已验真输出"
SUBS_CHECK_CONFIG_FILE = Path(os.environ.get("SUBS_CHECK_CONFIG_FILE", APP_DIR / "subs-check" / "config" / "config.yaml"))
SUBS_CHECK_API_KEY = os.environ.get("SUBS_CHECK_API_KEY", "").strip()
SUBS_CHECK_OUTPUT_DIR = Path(os.environ.get("SUBS_CHECK_OUTPUT_DIR", APP_DIR / "subs-check" / "output"))
FAILED_NODE_CHECK_STATUSES = {"真测失败", "proxy_failed", "failed"}
OK_NODE_CHECK_STATUSES = {"proxy_ok", "真可用"}
INCONCLUSIVE_NODE_CHECK_STATUSES = {"proxy_skipped", "proxy_unsupported", "tester_unavailable", "skipped", "跳过测试"}
INTERNAL_SUBS_CHECK_HOSTS = {
    host.strip().lower()
    for host in os.environ.get("INTERNAL_SUBS_CHECK_HOSTS", "sub-service,sub-service:8001,127.0.0.1:8001,localhost:8001").split(",")
    if host.strip()
}


def get_secret_key() -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_file = DATA_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    key = secrets.token_urlsafe(48)
    key_file.write_text(key, encoding="utf-8")
    return key


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or get_secret_key()


@app.after_request
def prevent_admin_cache(response: Response) -> Response:
    if request.path == "/login" or request.path == "/logout" or request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.vary.add("Cookie")
    return response


@app.route("/favicon.ico")
def favicon() -> Response:
    favicon_path = APP_DIR / "static" / "favicon.svg"
    if not favicon_path.exists():
        return Response(status=204)
    response = Response(favicon_path.read_text(encoding="utf-8"), mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def run_schema_migration(conn: sqlite3.Connection, sql: str) -> None:
    try:
        conn.execute(sql)
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        if "duplicate column name" not in message:
            raise


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw TEXT NOT NULL UNIQUE,
                protocol TEXT NOT NULL DEFAULT 'unknown',
                name TEXT NOT NULL DEFAULT 'node',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS upstreams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                prefix TEXT NOT NULL DEFAULT '',
                last_status TEXT NOT NULL DEFAULT '未同步',
                last_count INTEGER NOT NULL DEFAULT 0,
                last_synced_at TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS upstream_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upstream_id INTEGER NOT NULL,
                raw TEXT NOT NULL,
                clash_proxy_json TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT 'unknown',
                name TEXT NOT NULL DEFAULT 'node',
                created_at TEXT NOT NULL,
                UNIQUE(upstream_id, raw),
                FOREIGN KEY(upstream_id) REFERENCES upstreams(id) ON DELETE CASCADE
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(nodes)")}
        migrations = {
            "display_name": "ALTER TABLE nodes ADD COLUMN display_name TEXT NOT NULL DEFAULT ''",
            "last_latency_ms": "ALTER TABLE nodes ADD COLUMN last_latency_ms INTEGER",
            "last_tested_at": "ALTER TABLE nodes ADD COLUMN last_tested_at TEXT",
            "test_status": "ALTER TABLE nodes ADD COLUMN test_status TEXT NOT NULL DEFAULT '未测速'",
        }
        for column, sql in migrations.items():
            if column not in columns:
                run_schema_migration(conn, sql)
        upstream_columns = {row["name"] for row in conn.execute("PRAGMA table_info(upstreams)")}
        upstream_migrations = {
            "source_type": "ALTER TABLE upstreams ADD COLUMN source_type TEXT NOT NULL DEFAULT 'url'",
            "content": "ALTER TABLE upstreams ADD COLUMN content TEXT NOT NULL DEFAULT ''",
            "update_interval_minutes": "ALTER TABLE upstreams ADD COLUMN update_interval_minutes INTEGER NOT NULL DEFAULT 60",
            "last_checked_at": "ALTER TABLE upstreams ADD COLUMN last_checked_at TEXT NOT NULL DEFAULT ''",
            "only_nodes": "ALTER TABLE upstreams ADD COLUMN only_nodes INTEGER NOT NULL DEFAULT 1",
            "last_raw_count": "ALTER TABLE upstreams ADD COLUMN last_raw_count INTEGER NOT NULL DEFAULT 0",
        }
        for column, sql in upstream_migrations.items():
            if column not in upstream_columns:
                run_schema_migration(conn, sql)
        upstream_node_columns = {row["name"] for row in conn.execute("PRAGMA table_info(upstream_nodes)")}
        upstream_node_migrations = {
            "clash_proxy_json": "ALTER TABLE upstream_nodes ADD COLUMN clash_proxy_json TEXT NOT NULL DEFAULT ''",
        }
        for column, sql in upstream_node_migrations.items():
            if column not in upstream_node_columns:
                run_schema_migration(conn, sql)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                days INTEGER NOT NULL DEFAULT 30,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscribers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                traffic_key TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                expire_at TEXT NOT NULL DEFAULT '',
                total_bytes INTEGER NOT NULL DEFAULT 0,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT '',
                target_id TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_bytes INTEGER NOT NULL DEFAULT 0,
                download_bytes INTEGER NOT NULL DEFAULT 0,
                connections INTEGER NOT NULL DEFAULT 0,
                anomalies INTEGER NOT NULL DEFAULT 0,
                blocked_ips INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                traffic_key TEXT NOT NULL DEFAULT '',
                user_name TEXT NOT NULL DEFAULT '',
                source_ip TEXT NOT NULL DEFAULT '',
                node TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT '',
                upload_bytes INTEGER NOT NULL DEFAULT 0,
                download_bytes INTEGER NOT NULL DEFAULT 0,
                risk TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_snapshots_created_at ON traffic_snapshots(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_events_created_at ON traffic_events(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_events_traffic_key ON traffic_events(traffic_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_events_risk ON traffic_events(risk)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS geo_cache (
                host TEXT PRIMARY KEY,
                resolved_ip TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT '',
                country_code TEXT NOT NULL DEFAULT '',
                continent TEXT NOT NULL DEFAULT '',
                city TEXT NOT NULL DEFAULT '',
                asn TEXT NOT NULL DEFAULT '',
                org TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'unknown',
                error TEXT NOT NULL DEFAULT '',
                checked_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_geo_cache_resolved_ip ON geo_cache(resolved_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_geo_cache_continent ON geo_cache(continent)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_geo_cache_checked_at ON geo_cache(checked_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_checks (
                asset_key TEXT PRIMARY KEY,
                latency_ms INTEGER,
                status TEXT NOT NULL DEFAULT '未测速',
                checked_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_check_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_key TEXT NOT NULL,
                latency_ms INTEGER,
                status TEXT NOT NULL DEFAULT '',
                checked_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_check_history_asset_time ON node_check_history(asset_key, checked_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_metadata (
                asset_key TEXT PRIMARY KEY,
                source TEXT NOT NULL DEFAULT '',
                subs_check_name TEXT NOT NULL DEFAULT '',
                speed_label TEXT NOT NULL DEFAULT '',
                ip_risk TEXT NOT NULL DEFAULT '',
                media_json TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_metadata_source ON node_metadata(source)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subs_check_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT '',
                node_count INTEGER NOT NULL DEFAULT 0,
                checking INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_subs_check_runs_created ON subs_check_runs(created_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subs_check_quality_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_key TEXT NOT NULL UNIQUE,
                output_hash TEXT NOT NULL,
                input_count INTEGER NOT NULL DEFAULT 0,
                output_count INTEGER NOT NULL DEFAULT 0,
                matched_output_count INTEGER NOT NULL DEFAULT 0,
                min_speed_kbps INTEGER NOT NULL DEFAULT 0,
                checked_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_subs_quality_runs_checked ON subs_check_quality_runs(checked_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_quality_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                asset_key TEXT NOT NULL,
                identity_key TEXT NOT NULL,
                passed INTEGER NOT NULL DEFAULT 0,
                output_name TEXT NOT NULL DEFAULT '',
                speed_label TEXT NOT NULL DEFAULT '',
                checked_at TEXT NOT NULL,
                UNIQUE(run_id, asset_key),
                FOREIGN KEY(run_id) REFERENCES subs_check_quality_runs(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_quality_asset_run ON node_quality_observations(asset_key, run_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_quality_run_passed ON node_quality_observations(run_id, passed)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_monitor_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_key TEXT NOT NULL,
                cpu_percent REAL NOT NULL DEFAULT 0,
                memory_percent REAL NOT NULL DEFAULT 0,
                inbound_bps INTEGER NOT NULL DEFAULT 0,
                outbound_bps INTEGER NOT NULL DEFAULT 0,
                connections INTEGER NOT NULL DEFAULT 0,
                load_status TEXT NOT NULL DEFAULT '',
                reported_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_monitor_asset_created ON node_monitor_snapshots(asset_key, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_monitor_created_at ON node_monitor_snapshots(created_at)")
        subscriber_columns = {row["name"] for row in conn.execute("PRAGMA table_info(subscribers)")}
        if "traffic_key" not in subscriber_columns:
            run_schema_migration(conn, "ALTER TABLE subscribers ADD COLUMN traffic_key TEXT NOT NULL DEFAULT ''")
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribers_traffic_key ON subscribers(traffic_key) WHERE traffic_key <> ''"
            )
        except sqlite3.IntegrityError:
            pass
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES ('admin_user', ?)", (ADMIN_USER,))
        conn.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES ('admin_password_hash', ?)",
            (generate_password_hash(ADMIN_PASSWORD),),
        )


def clean_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def parse_gb(value: str) -> int:
    try:
        gb = float((value or "0").strip())
    except ValueError:
        gb = 0
    return max(0, int(gb * 1024 * 1024 * 1024))


def bytes_to_gb(value: int) -> str:
    if not value:
        return "0"
    gb = value / 1024 / 1024 / 1024
    return f"{gb:.2f}".rstrip("0").rstrip(".")


def format_bytes(value: int) -> str:
    if not value:
        return "0 B"
    gb = value / 1024 / 1024 / 1024
    if gb >= 1:
        return f"{gb:.2f} GB"
    mb = value / 1024 / 1024
    return f"{mb:.1f} MB"


def expire_epoch(expire_at: str) -> int:
    if not expire_at:
        return 253402300799
    try:
        dt = datetime.strptime(expire_at, "%Y-%m-%d")
        return int(dt.replace(hour=23, minute=59, second=59).timestamp())
    except ValueError:
        return 253402300799


def add_days(days: int, base: datetime | None = None) -> str:
    base = base or datetime.now()
    return (base.date() + timedelta(days=max(0, days))).isoformat()


def days_until(expire_at: str) -> int | None:
    if not expire_at:
        return None
    try:
        return (datetime.strptime(expire_at, "%Y-%m-%d").date() - datetime.now().date()).days
    except ValueError:
        return None


def subscriber_status(row: sqlite3.Row | dict) -> str:
    if not row["enabled"]:
        return "停用"
    if row["expire_at"]:
        try:
            if datetime.strptime(row["expire_at"], "%Y-%m-%d").date() < datetime.now().date():
                return "已过期"
        except ValueError:
            return "日期错误"
    if row["total_bytes"] and row["used_bytes"] >= row["total_bytes"]:
        return "流量用完"
    return "正常"


def subscriber_allowed(row: sqlite3.Row | dict) -> bool:
    return subscriber_status(row) == "正常"


def new_subscriber_token() -> str:
    return secrets.token_urlsafe(18).replace("-", "").replace("_", "")


def enrich_subscriber(row: sqlite3.Row | dict) -> dict:
    item = dict(row)
    item["status"] = subscriber_status(row)
    total = int(row["total_bytes"] or 0)
    used = int(row["used_bytes"] or 0)
    remaining = max(0, total - used)
    expire_days = days_until(row["expire_at"])
    usage_percent = 0 if total == 0 else min(100, round(used / total * 100))
    warnings = []
    if item["status"] in {"已过期", "流量用完", "停用", "日期错误"}:
        warnings.append(item["status"])
    elif expire_days is not None and expire_days <= 3:
        warnings.append(f"{max(expire_days, 0)} 天内到期")
    if total and remaining <= total * 0.1 and item["status"] == "正常":
        warnings.append("流量低")
    item["total_gb"] = bytes_to_gb(total)
    item["used_gb"] = bytes_to_gb(used)
    item["total_label"] = "不限" if total == 0 else format_bytes(total)
    item["used_label"] = format_bytes(used)
    item["remaining_label"] = "不限" if total == 0 else format_bytes(remaining)
    item["expire_days"] = expire_days
    item["usage_percent"] = usage_percent
    item["warning_label"] = " / ".join(warnings)
    item["is_warning"] = bool(warnings)
    if is_dingyue_subscriber(row):
        item["links"] = {
            "auto": DINGYUE_PATH,
            "clash": f"{DINGYUE_PATH}/clash",
            "hiddify": f"{DINGYUE_PATH}/hiddify",
            "v2ray": f"{DINGYUE_PATH}/v2ray",
            "surge": f"{DINGYUE_PATH}/surge",
            "qx": f"{DINGYUE_PATH}/qx",
        }
        item["short_subscription_link"] = DINGYUE_PATH
    else:
        item["links"] = {
            "auto": f"/sub/{row['token']}",
            "clash": f"/sub/{row['token']}/clash",
            "hiddify": f"/sub/{row['token']}/hiddify",
            "v2ray": f"/sub/{row['token']}/v2ray",
            "surge": f"/sub/{row['token']}/surge",
            "qx": f"/sub/{row['token']}/qx",
        }
        item["short_subscription_link"] = ""
    return item


def is_dingyue_subscriber(row: sqlite3.Row | dict) -> bool:
    return str(row["name"] if "name" in row.keys() else row.get("name", "")).strip().lower() == DINGYUE_SUBSCRIBER_NAME.lower()


def list_subscribers() -> list[dict]:
    with db() as conn:
        rows = []
        for row in conn.execute("SELECT * FROM subscribers ORDER BY id DESC"):
            item = enrich_subscriber(row)
            rows.append(item)
        return rows


def filter_subscribers(users: list[dict], query: str = "", status_filter: str = "") -> list[dict]:
    query = (query or "").strip().lower()
    status_filter = (status_filter or "").strip()
    result = users
    if query:
        def matches(user: dict) -> bool:
            haystack = " ".join(
                str(user.get(key, ""))
                for key in ("name", "note", "traffic_key", "status", "expire_at")
            ).lower()
            return query in haystack

        result = [user for user in result if matches(user)]
    if status_filter == "warning":
        result = [user for user in result if user["is_warning"]]
    elif status_filter == "missing_traffic_key":
        result = [user for user in result if not user.get("traffic_key")]
    elif status_filter:
        result = [user for user in result if user["status"] == status_filter]
    return result


def subscriber_summary(users: list[dict]) -> dict:
    return {
        "total": len(users),
        "active": len([user for user in users if user["status"] == "正常"]),
        "warning": len([user for user in users if user["is_warning"]]),
        "expired": len([user for user in users if user["status"] in {"已过期", "流量用完"}]),
    }


def percent(part: int | float, total: int | float) -> int:
    total = int(total or 0)
    if total <= 0:
        return 0
    return max(0, min(100, round(float(part or 0) / total * 100)))


def chart_items(items: list[tuple[str, int]], total: int | None = None) -> list[dict]:
    total = total if total is not None else sum(value for _label, value in items)
    return [
        {"label": label, "value": value, "percent": percent(value, total)}
        for label, value in items
    ]


def pagination_args(default_per_page: int = 20, max_per_page: int = 100) -> tuple[int, int]:
    page = max(1, safe_int(request.args.get("page"), 1))
    per_page = max(1, safe_int(request.args.get("per_page"), default_per_page))
    return page, min(per_page, max_per_page)


def paginate_items(items: list[dict], page: int, per_page: int) -> dict:
    total = len(items)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    start = (page - 1) * per_page
    query_args = request.args.to_dict(flat=True)
    def page_url(number: int) -> str:
        args = dict(query_args)
        args["page"] = str(number)
        args["per_page"] = str(per_page)
        return url_for(request.endpoint, **args)
    page_numbers = [number for number in range(max(1, page - 2), min(pages, page + 2) + 1)]
    return {
        "items": items[start:start + per_page],
        "total": total,
        "page": page,
        "pages": pages,
        "per_page": per_page,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_page": max(1, page - 1),
        "next_page": min(pages, page + 1),
        "prev_url": page_url(max(1, page - 1)),
        "next_url": page_url(min(pages, page + 1)),
        "page_urls": [{"number": number, "url": page_url(number)} for number in page_numbers],
        "query_args": query_args,
    }


def paginate_db_items(items: list[dict], total: int, page: int, per_page: int) -> dict:
    pages = max(1, (int(total or 0) + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    query_args = request.args.to_dict(flat=True)

    def page_url(number: int) -> str:
        args = dict(query_args)
        args["page"] = str(number)
        args["per_page"] = str(per_page)
        return url_for(request.endpoint, **args)

    page_numbers = [number for number in range(max(1, page - 2), min(pages, page + 2) + 1)]
    return {
        "items": items,
        "total": int(total or 0),
        "page": page,
        "pages": pages,
        "per_page": per_page,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_page": max(1, page - 1),
        "next_page": min(pages, page + 1),
        "prev_url": page_url(max(1, page - 1)),
        "next_url": page_url(min(pages, page + 1)),
        "page_urls": [{"number": number, "url": page_url(number)} for number in page_numbers],
        "query_args": query_args,
    }


def dashboard_charts(rows: list[sqlite3.Row], upstreams: list[dict], upstream_node_count: int) -> dict:
    manual_count = len(rows)
    total_nodes = manual_count + upstream_node_count
    protocol_counts: dict[str, int] = {}
    for row in rows:
        protocol = row["protocol"] or "unknown"
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    for item in load_upstream_node_items(enabled_only=False):
        protocol = item.get("protocol") or "unknown"
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    protocol_items = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)[:6]
    enabled_ok = len([item for item in upstreams if item["enabled"] and item.get("last_status") != "同步失败"])
    enabled_bad = len([item for item in upstreams if item["enabled"] and item.get("last_status") == "同步失败"])
    disabled = len([item for item in upstreams if not item["enabled"]])
    return {
        "source": chart_items([("手动节点", manual_count), ("上游缓存", upstream_node_count)], total_nodes),
        "protocols": chart_items(protocol_items),
        "upstream_health": chart_items([("正常", enabled_ok), ("异常", enabled_bad), ("停用", disabled)], len(upstreams)),
    }


def user_charts(users: list[dict]) -> dict:
    normal = len([user for user in users if user["status"] == "正常" and not user["is_warning"]])
    warning = len([user for user in users if user["is_warning"]])
    unavailable = len([user for user in users if user["status"] != "正常"])
    top_usage = sorted(users, key=lambda user: int(user.get("used_bytes") or 0), reverse=True)[:6]
    return {
        "status": chart_items([("正常", normal), ("预警", warning), ("不可用", unavailable)], len(users)),
        "top_usage": top_usage,
    }


def list_plans() -> list[dict]:
    with db() as conn:
        rows = []
        for row in conn.execute("SELECT * FROM plans ORDER BY id DESC"):
            item = dict(row)
            item["total_gb"] = bytes_to_gb(row["total_bytes"])
            item["total_label"] = "不限" if row["total_bytes"] == 0 else format_bytes(row["total_bytes"])
            rows.append(item)
        return rows


def get_plan(plan_id: str) -> sqlite3.Row | None:
    if not plan_id:
        return None
    try:
        pid = int(plan_id)
    except ValueError:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM plans WHERE id = ?", (pid,)).fetchone()


def get_subscriber(user_id: int) -> dict | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM subscribers WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None
    item = enrich_subscriber(row)
    return item


def get_subscriber_by_token(token: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM subscribers WHERE token = ?", (token,)).fetchone()


def get_dingyue_subscriber() -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM subscribers WHERE lower(name) = lower(?) ORDER BY id LIMIT 1",
            (DINGYUE_SUBSCRIBER_NAME,),
        ).fetchone()


def ensure_dingyue_subscriber() -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        row = conn.execute(
            "SELECT id, traffic_key FROM subscribers WHERE lower(name) = lower(?) ORDER BY id LIMIT 1",
            (DINGYUE_SUBSCRIBER_NAME,),
        ).fetchone()
        if row:
            if not str(row["traffic_key"] or "").strip():
                try:
                    conn.execute(
                        "UPDATE subscribers SET traffic_key = ?, updated_at = ? WHERE id = ?",
                        (DINGYUE_SUBSCRIBER_NAME, now, row["id"]),
                    )
                except sqlite3.IntegrityError:
                    pass
            return
        token = new_subscriber_token()
        traffic_key = DINGYUE_SUBSCRIBER_NAME
        try:
            conn.execute(
                """
                INSERT INTO subscribers(name, token, traffic_key, enabled, expire_at, total_bytes, used_bytes, note, created_at, updated_at)
                VALUES (?, ?, ?, 1, '', 0, 0, ?, ?, ?)
                """,
                (
                    DINGYUE_SUBSCRIBER_NAME,
                    token,
                    traffic_key,
                    f"系统自动创建的短链会员，订阅入口 {DINGYUE_PATH}",
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            conn.execute(
                """
                INSERT INTO subscribers(name, token, traffic_key, enabled, expire_at, total_bytes, used_bytes, note, created_at, updated_at)
                VALUES (?, ?, ?, 1, '', 0, 0, ?, ?, ?)
                """,
                (
                    DINGYUE_SUBSCRIBER_NAME,
                    new_subscriber_token(),
                    token,
                    f"系统自动创建的短链会员，订阅入口 {DINGYUE_PATH}",
                    now,
                    now,
                ),
            )


def report_subscriber_usage(traffic_key: str, used_bytes: int | None = None, delta_bytes: int | None = None) -> bool:
    if not traffic_key:
        return False
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        row = conn.execute("SELECT id, used_bytes FROM subscribers WHERE traffic_key = ?", (traffic_key,)).fetchone()
        if not row:
            return False
        if used_bytes is not None:
            new_used = max(0, int(used_bytes))
        else:
            new_used = max(0, int(row["used_bytes"]) + max(0, int(delta_bytes or 0)))
        conn.execute("UPDATE subscribers SET used_bytes = ?, updated_at = ? WHERE id = ?", (new_used, now, row["id"]))
    return True


def audit(action: str, target_type: str = "", target_id: str | int = "", message: str = "") -> None:
    try:
        actor = current_admin_user() if session.get("admin") else "api"
    except RuntimeError:
        actor = "system"
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",", 1)[0].strip()
    except RuntimeError:
        ip = ""
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs(action, target_type, target_id, message, actor, ip, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (action, target_type, str(target_id or ""), message, actor, ip, now),
        )


def list_audit_logs(limit: int = 80) -> list[dict]:
    with db() as conn:
        return [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 200)),),
            )
        ]


def make_qr_svg(text: str) -> bytes:
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage)
    output = io.BytesIO()
    img.save(output)
    return output.getvalue()


def backup_current_nodes() -> None:
    nodes = load_nodes(renamed=False)
    if not nodes:
        return
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    (BACKUP_DIR / f"nodes-{stamp}.txt").write_text("\n".join(nodes) + "\n", encoding="utf-8")


def backup_subscribers() -> None:
    with db() as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM subscribers ORDER BY id")]
    if not rows:
        return
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    (BACKUP_DIR / f"subscribers-{stamp}.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def create_database_backup() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    target = BACKUP_DIR / f"sub-db-{stamp}.db"
    with sqlite3.connect(DB_FILE) as source, sqlite3.connect(target) as dest:
        source.backup(dest)
    return target


def list_database_backups() -> list[dict]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backups = []
    for path in sorted(BACKUP_DIR.glob("sub-db-*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        backups.append(
            {
                "name": path.name,
                "size": format_bytes(path.stat().st_size),
                "created": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return backups


def restore_database_backup(name: str) -> bool:
    if not name.startswith("sub-db-") or not name.endswith(".db") or "/" in name or "\\" in name:
        return False
    source = BACKUP_DIR / name
    if not source.exists():
        return False
    safety = create_database_backup()
    with sqlite3.connect(source) as src, sqlite3.connect(DB_FILE) as dest:
        src.backup(dest)
    (BACKUP_DIR / f"before-restore-{safety.name}").write_bytes(safety.read_bytes())
    return True


def run_backup_drill() -> dict:
    started = datetime.now().isoformat(timespec="seconds")
    target = create_database_backup()
    ok = False
    message = ""
    try:
        with sqlite3.connect(target) as conn:
            check = conn.execute("PRAGMA quick_check").fetchone()[0]
            tables = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        ok = check == "ok" and int(tables or 0) > 0
        message = f"{target.name} · quick_check={check} · tables={tables}"
    except Exception as exc:
        message = f"{target.name} · 演练失败：{str(exc)[:180]}"
    set_setting("backup_drill_at", started)
    set_setting("backup_drill_status", "ok" if ok else "failed")
    set_setting("backup_drill_message", message)
    return {"ok": ok, "created_at": started, "message": message, "backup": target.name}


def backup_drill_status() -> dict:
    status = get_setting("backup_drill_status", "")
    checked_at = get_setting("backup_drill_at", "")
    message = get_setting("backup_drill_message", "")
    return {
        "ok": status == "ok",
        "status": status or "never",
        "label": "通过" if status == "ok" else "失败" if status == "failed" else "未演练",
        "checked_at": checked_at,
        "checked_label": relative_time(checked_at) if checked_at else "从未",
        "message": message or "还没有做过恢复演练",
    }


def latest_backup(prefix: str) -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    matches = sorted(BACKUP_DIR.glob(f"{prefix}*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not matches:
        return {"name": "无", "created": "从未", "size": "0 B"}
    path = matches[0]
    return {
        "name": path.name,
        "created": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "size": format_bytes(path.stat().st_size),
    }


def backup_status() -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "dir": str(BACKUP_DIR),
        "writable": os.access(BACKUP_DIR, os.W_OK),
        "database": latest_backup("sub-db-"),
        "nodes": latest_backup("nodes-"),
        "subscribers": latest_backup("subscribers-"),
        "drill": backup_drill_status(),
    }


def sync_nodes_file() -> None:
    NODES_FILE.parent.mkdir(parents=True, exist_ok=True)
    nodes = load_nodes(renamed=False)
    NODES_FILE.write_text("\n".join(nodes) + ("\n" if nodes else ""), encoding="utf-8")


def migrate_nodes_file() -> None:
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    if count or not NODES_FILE.exists():
        return
    add_nodes(clean_lines(NODES_FILE.read_text(encoding="utf-8")), make_backup=False)


def parse_node(line: str) -> dict:
    line = line.strip()
    if line.startswith(("http://", "https://")):
        return {"protocol": "http", "name": extract_name(line), "raw": line}
    if line.startswith("ss://"):
        return {"protocol": "ss", "name": extract_name(line), "raw": line}
    if line.startswith("vmess://"):
        try:
            decoded = b64decode_text(line[8:])
            info = json.loads(decoded)
            return {"protocol": "vmess", "name": info.get("ps") or info.get("remark") or info.get("name") or "vmess", "raw": line}
        except Exception:
            return {"protocol": "vmess", "name": "vmess", "raw": line}
    if line.startswith("vless://"):
        return {"protocol": "vless", "name": extract_name(line), "raw": line}
    if line.startswith("trojan://"):
        return {"protocol": "trojan", "name": extract_name(line), "raw": line}
    if line.startswith(("hysteria://", "hysteria2://", "hy2://")):
        return {"protocol": "hysteria", "name": extract_name(line), "raw": line}
    if line.startswith("ssr://"):
        return {"protocol": "ssr", "name": extract_name(line), "raw": line}
    if line.startswith("tuic://"):
        return {"protocol": "tuic", "name": extract_name(line), "raw": line}
    return {"protocol": "unknown", "name": "unknown", "raw": line}


def extract_name(line: str) -> str:
    if "#" in line:
        return unquote(line.rsplit("#", 1)[-1].strip()) or "node"
    return "node"


def b64decode_text(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode("utf-8", errors="replace")


def b64encode_text(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode().rstrip("=")


SUPPORTED_NODE_PREFIXES = ("ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "http://", "https://")


def is_node_uri(value: str) -> bool:
    return value.strip().startswith(SUPPORTED_NODE_PREFIXES)


def decode_possible_base64(text: str) -> str:
    compact = "".join(text.strip().split())
    if not compact:
        return ""
    try:
        return b64decode_text(compact)
    except Exception:
        try:
            padding = "=" * (-len(compact) % 4)
            return base64.b64decode(compact + padding).decode("utf-8", errors="replace")
        except Exception:
            return ""


def parse_subscription_items_from_text(text: str) -> list[dict]:
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return []
    nodes = [line.strip() for line in text.splitlines() if is_node_uri(line.strip())]
    if nodes:
        return dedupe_subscription_items([subscription_item_from_raw(node) for node in nodes])
    decoded = decode_possible_base64(text)
    if decoded and decoded != text:
        nodes = [line.strip() for line in decoded.splitlines() if is_node_uri(line.strip())]
        if nodes:
            return dedupe_subscription_items([subscription_item_from_raw(node) for node in nodes])
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            return dedupe_subscription_items(clash_proxies_to_subscription_items(data["proxies"]))
    except Exception:
        pass
    return []


def parse_subscription_text(text: str) -> list[str]:
    return [item["raw"] for item in parse_subscription_items_from_text(text)]


def subscription_item_from_raw(raw: str, clash_proxy: dict | None = None) -> dict:
    parsed = parse_node(raw)
    item = {
        "raw": parsed["raw"],
        "protocol": parsed["protocol"],
        "name": parsed["name"],
        "clash_proxy": normalize_clash_proxy(clash_proxy) if clash_proxy else None,
    }
    if item["clash_proxy"] and item["clash_proxy"].get("name"):
        item["name"] = str(item["clash_proxy"]["name"])
    return item


def normalize_clash_proxy(proxy: dict | None) -> dict | None:
    if not isinstance(proxy, dict):
        return None
    try:
        normalized = json.loads(json.dumps(proxy, ensure_ascii=False, default=str))
    except Exception:
        return None
    if not isinstance(normalized, dict):
        return None
    return normalized


def dedupe_subscription_items(items: list[dict]) -> list[dict]:
    result = []
    seen = set()
    for item in items:
        raw = str(item.get("raw") or "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        item["raw"] = raw
        result.append(item)
    return result


def normalized_identity_protocol(value: str) -> str:
    protocol = str(value or "unknown").strip().lower()
    return {"hy2": "hysteria2", "hysteria": "hysteria2", "https": "http"}.get(protocol, protocol)


def normalized_identity_host(value: str) -> str:
    return str(value or "").strip().strip("[]").rstrip(".").lower()


def proxy_identity_parts(proxy: dict) -> dict:
    protocol = normalized_identity_protocol(proxy.get("type"))
    host = normalized_identity_host(proxy.get("server"))
    port = safe_int(proxy.get("port"))
    primary = ""
    secondary = ""
    if protocol in {"vmess", "vless"}:
        primary = str(proxy.get("uuid") or proxy.get("id") or "").strip().lower()
    elif protocol in {"trojan", "hysteria2"}:
        primary = str(proxy.get("password") or proxy.get("auth") or proxy.get("auth-str") or "").strip()
    elif protocol == "ss":
        primary = str(proxy.get("cipher") or "").strip().lower()
        secondary = str(proxy.get("password") or "").strip()
    elif protocol == "tuic":
        primary = str(proxy.get("uuid") or proxy.get("username") or "").strip().lower()
        secondary = str(proxy.get("password") or "").strip()
    elif protocol == "http":
        primary = str(proxy.get("username") or proxy.get("user") or "").strip()
        secondary = str(proxy.get("password") or proxy.get("pass") or "").strip()
    return {"protocol": protocol, "host": host, "port": port, "primary": primary, "secondary": secondary}


def raw_identity_parts(raw: str) -> dict:
    raw = str(raw or "").strip()
    protocol = normalized_identity_protocol(parse_node(raw).get("protocol"))
    try:
        if raw.startswith("vmess://"):
            info = json.loads(b64decode_text(raw[8:]))
            return {
                "protocol": "vmess",
                "host": normalized_identity_host(info.get("add")),
                "port": safe_int(info.get("port")),
                "primary": str(info.get("id") or "").strip().lower(),
                "secondary": "",
            }
        if raw.startswith("ssr://"):
            decoded = b64decode_text(raw[6:])
            core = decoded.split("/?", 1)[0].split(":")
            if len(core) >= 6:
                return {
                    "protocol": "ssr",
                    "host": normalized_identity_host(core[0]),
                    "port": safe_int(core[1]),
                    "primary": str(core[3]).strip().lower(),
                    "secondary": str(core[5]).strip(),
                }
        if raw.startswith("ss://"):
            payload = raw[5:].split("#", 1)[0]
            if "@" not in payload:
                decoded = b64decode_text(payload.split("?", 1)[0])
                return raw_identity_parts("ss://" + decoded)
            userinfo, endpoint = payload.rsplit("@", 1)
            try:
                decoded_userinfo = b64decode_text(userinfo)
            except Exception:
                decoded_userinfo = unquote(userinfo)
            cipher, password = (decoded_userinfo.split(":", 1) + [""])[:2]
            parsed = urlparse("ss://x@" + endpoint)
            return {
                "protocol": "ss",
                "host": normalized_identity_host(parsed.hostname),
                "port": safe_int(parsed.port),
                "primary": cipher.strip().lower(),
                "secondary": password.strip(),
            }
        parsed = urlparse(raw)
        query = parse_qs(parsed.query)
        primary = unquote(parsed.username or "")
        secondary = unquote(parsed.password or "")
        if protocol == "hysteria2" and not primary:
            primary = str((query.get("auth") or query.get("auth-str") or [""])[0])
        if protocol == "http" and parsed.username:
            primary = unquote(parsed.username)
        return {
            "protocol": protocol,
            "host": normalized_identity_host(parsed.hostname),
            "port": safe_int(parsed.port or (80 if parsed.scheme == "http" else 443)),
            "primary": primary.strip().lower() if protocol in {"vmess", "vless", "tuic"} else primary.strip(),
            "secondary": secondary.strip(),
        }
    except Exception:
        endpoint = node_endpoint(raw)
        return {
            "protocol": protocol,
            "host": normalized_identity_host(endpoint[0] if endpoint else ""),
            "port": safe_int(endpoint[1] if endpoint else 0),
            "primary": "",
            "secondary": "",
        }


def node_identity_key(item: dict | str) -> str:
    if isinstance(item, str):
        parts = raw_identity_parts(item)
    else:
        proxy = item.get("clash_proxy")
        if not proxy and item.get("clash_proxy_json"):
            try:
                proxy = json.loads(item.get("clash_proxy_json") or "")
            except Exception:
                proxy = None
        parts = proxy_identity_parts(proxy) if isinstance(proxy, dict) else raw_identity_parts(item.get("raw", ""))
    if not parts.get("host") or not parts.get("port"):
        return ""
    canonical = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def clash_proxy_type_counts(text: str) -> dict[str, int]:
    try:
        data = yaml.safe_load(text)
    except Exception:
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        return {}
    counts: dict[str, int] = {}
    for proxy in data["proxies"]:
        if not isinstance(proxy, dict):
            continue
        ptype = str(proxy.get("type", "unknown")).lower() or "unknown"
        counts[ptype] = counts.get(ptype, 0) + 1
    return counts


def upstream_parse_note(text: str, parsed_count: int) -> str:
    counts = clash_proxy_type_counts(text)
    if not counts:
        return ""
    supported = {"ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "ssr", "http", "https"}
    skipped = {key: value for key, value in counts.items() if key not in supported}
    if not skipped:
        return ""
    skipped_label = "、".join(f"{key} {value} 条" for key, value in sorted(skipped.items()))
    total = sum(counts.values())
    return f"已解析 {parsed_count}/{total} 条，跳过不支持类型：{skipped_label}"


def clash_proxies_to_uris(proxies: list) -> list[str]:
    return [item["raw"] for item in clash_proxies_to_subscription_items(proxies)]


def clash_proxies_to_subscription_items(proxies: list) -> list[dict]:
    nodes = []
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        raw = clash_proxy_to_uri(proxy)
        if raw:
            nodes.append(subscription_item_from_raw(raw, proxy))
    return nodes


def clash_proxy_to_uri(proxy: dict) -> str:
    ptype = str(proxy.get("type", "")).lower()
    name = quote(str(proxy.get("name") or ptype or "node"), safe="")
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return ""
    if ptype == "trojan":
        password = quote(str(proxy.get("password", "")), safe="")
        query = []
        if proxy.get("sni") or proxy.get("servername"):
            query.append("sni=" + quote(str(proxy.get("sni") or proxy.get("servername")), safe=""))
        if proxy.get("alpn"):
            alpn = proxy.get("alpn")
            if isinstance(alpn, list):
                alpn = ",".join(str(item) for item in alpn)
            query.append("alpn=" + quote(str(alpn), safe=","))
        if proxy.get("client-fingerprint"):
            query.append("fp=" + quote(str(proxy.get("client-fingerprint")), safe=""))
        if proxy.get("skip-cert-verify"):
            query.append("allowInsecure=1")
        if proxy.get("udp"):
            query.append("udp=1")
        query.append("type=" + quote(str(proxy.get("network") or "tcp"), safe=""))
        if str(proxy.get("network") or "").lower() == "ws":
            ws_opts = proxy.get("ws-opts") or {}
            if isinstance(ws_opts, dict):
                if ws_opts.get("path"):
                    query.append("path=" + quote(str(ws_opts.get("path")), safe="/"))
                headers = ws_opts.get("headers") or {}
                if isinstance(headers, dict):
                    host = headers.get("Host") or headers.get("host")
                    if host:
                        query.append("host=" + quote(str(host), safe=""))
        if str(proxy.get("network") or "").lower() == "grpc":
            grpc_opts = proxy.get("grpc-opts") or {}
            if isinstance(grpc_opts, dict):
                service = grpc_opts.get("grpc-service-name") or grpc_opts.get("serviceName") or grpc_opts.get("service-name")
                if service:
                    query.append("serviceName=" + quote(str(service), safe=""))
        return f"trojan://{password}@{server}:{port}{('?' + '&'.join(query)) if query else ''}#{name}"
    if ptype == "vmess":
        info = {
            "v": "2",
            "ps": unquote(name),
            "add": server,
            "port": str(port),
            "id": proxy.get("uuid", ""),
            "aid": str(proxy.get("alterId", proxy.get("alter-id", 0))),
            "scy": proxy.get("cipher", "auto"),
            "net": proxy.get("network", "tcp"),
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls" if proxy.get("tls") else "",
            "sni": proxy.get("servername") or proxy.get("sni") or "",
        }
        if proxy.get("skip-cert-verify"):
            info["allowInsecure"] = 1
        ws_opts = proxy.get("ws-opts") or {}
        if isinstance(ws_opts, dict):
            info["path"] = ws_opts.get("path", "")
            headers = ws_opts.get("headers") or {}
            if isinstance(headers, dict):
                info["host"] = headers.get("Host") or headers.get("host") or ""
        http_opts = proxy.get("http-opts") or {}
        if isinstance(http_opts, dict) and str(proxy.get("network", "")).lower() == "http":
            paths = http_opts.get("path") or []
            headers = http_opts.get("headers") or {}
            if isinstance(paths, list) and paths:
                info["path"] = paths[0]
            elif isinstance(paths, str):
                info["path"] = paths
            if isinstance(headers, dict):
                host = headers.get("Host") or headers.get("host") or []
                if isinstance(host, list) and host:
                    info["host"] = host[0]
                elif isinstance(host, str):
                    info["host"] = host
        return "vmess://" + b64encode_text(json.dumps(info, ensure_ascii=False, separators=(",", ":")))
    if ptype == "vless":
        uuid = quote(str(proxy.get("uuid", "")), safe="")
        query = {"encryption": "none"}
        if proxy.get("tls"):
            query["security"] = "tls"
        if proxy.get("flow"):
            query["flow"] = str(proxy.get("flow"))
        if proxy.get("network"):
            query["type"] = str(proxy.get("network"))
        if proxy.get("servername") or proxy.get("sni"):
            query["sni"] = str(proxy.get("servername") or proxy.get("sni"))
        if proxy.get("client-fingerprint"):
            query["fp"] = str(proxy.get("client-fingerprint"))
        if proxy.get("alpn"):
            alpn = proxy.get("alpn")
            query["alpn"] = ",".join(str(item) for item in alpn) if isinstance(alpn, list) else str(alpn)
        if proxy.get("skip-cert-verify"):
            query["allowInsecure"] = "1"
        if proxy.get("udp"):
            query["udp"] = "1"
        ws_opts = proxy.get("ws-opts") or {}
        if isinstance(ws_opts, dict) and str(proxy.get("network") or "").lower() == "ws":
            if ws_opts.get("path"):
                query["path"] = str(ws_opts.get("path"))
            headers = ws_opts.get("headers") or {}
            if isinstance(headers, dict):
                host = headers.get("Host") or headers.get("host")
                if host:
                    query["host"] = str(host)
        reality_opts = proxy.get("reality-opts") or {}
        if isinstance(reality_opts, dict):
            if reality_opts.get("public-key"):
                query["security"] = "reality"
                query["pbk"] = str(reality_opts.get("public-key"))
            if reality_opts.get("short-id"):
                query["sid"] = str(reality_opts.get("short-id"))
        grpc_opts = proxy.get("grpc-opts") or {}
        if isinstance(grpc_opts, dict) and str(proxy.get("network") or "").lower() == "grpc":
            service = grpc_opts.get("grpc-service-name") or grpc_opts.get("serviceName") or grpc_opts.get("service-name")
            if service:
                query["serviceName"] = str(service)
        http_opts = proxy.get("http-opts") or {}
        if isinstance(http_opts, dict) and str(proxy.get("network") or "").lower() == "http":
            paths = http_opts.get("path") or []
            if isinstance(paths, list) and paths:
                query["path"] = str(paths[0])
            elif isinstance(paths, str):
                query["path"] = paths
            headers = http_opts.get("headers") or {}
            if isinstance(headers, dict):
                host = headers.get("Host") or headers.get("host") or []
                if isinstance(host, list) and host:
                    query["host"] = str(host[0])
                elif isinstance(host, str):
                    query["host"] = host
        qs = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='/')}" for k, v in query.items() if v)
        return f"vless://{uuid}@{server}:{port}?{qs}#{name}"
    if ptype == "ss":
        cipher = str(proxy.get("cipher", ""))
        password = str(proxy.get("password", ""))
        if not cipher or not password:
            return ""
        userinfo = b64encode_text(f"{cipher}:{password}")
        return f"ss://{userinfo}@{server}:{port}#{name}"
    if ptype in {"http", "https"}:
        username = quote(str(proxy.get("username") or proxy.get("user") or ""), safe="")
        password = quote(str(proxy.get("password") or proxy.get("pass") or ""), safe="")
        auth = f"{username}:{password}@" if username or password else ""
        scheme = "https" if ptype == "https" or proxy.get("tls") else "http"
        query = []
        if proxy.get("tls"):
            query.append("tls=1")
        if proxy.get("skip-cert-verify"):
            query.append("allowInsecure=1")
        return f"{scheme}://{auth}{server}:{port}{('?' + '&'.join(query)) if query else ''}#{name}"
    if ptype in {"hysteria2", "hy2"}:
        password = quote(str(proxy.get("password", "")), safe="")
        query = []
        if proxy.get("sni") or proxy.get("servername"):
            query.append("sni=" + quote(str(proxy.get("sni") or proxy.get("servername")), safe=""))
        if proxy.get("skip-cert-verify"):
            query.append("insecure=1")
        mport = proxy.get("mport") or proxy.get("ports")
        if mport:
            query.append("mport=" + quote(str(mport), safe="-:,"))
        if proxy.get("obfs"):
            query.append("obfs=" + quote(str(proxy.get("obfs")), safe=""))
        if proxy.get("obfs-password"):
            query.append("obfs-password=" + quote(str(proxy.get("obfs-password")), safe=""))
        return f"hysteria2://{password}@{server}:{port}{('?' + '&'.join(query)) if query else ''}#{name}"
    return ""


def dedupe_nodes(nodes: list[str]) -> list[str]:
    result = []
    seen = set()
    for node in nodes:
        node = node.strip()
        if node and node not in seen:
            seen.add(node)
            result.append(node)
    return result


def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def subscription_engine_mode() -> str:
    value = get_setting("subscription_engine_mode", SUBSCRIPTION_ENGINE_MODE).strip().lower()
    return value if value in {"balanced", "strict", "local"} else "balanced"


def subs_check_min_output_nodes() -> int:
    value = get_setting("subs_check_min_output_nodes", str(SUBS_CHECK_MIN_OUTPUT_NODES)).strip()
    try:
        count = int(value)
    except ValueError:
        return SUBS_CHECK_MIN_OUTPUT_NODES
    return max(0, min(count, 10000))


def subscription_engine_settings() -> dict:
    return {
        "mode": subscription_engine_mode(),
        "min_output_nodes": subs_check_min_output_nodes(),
        "mode_options": [
            {"value": "local", "label": "全量节点池", "hint": "仅在管理员明确选择时下发完整资产池"},
            {"value": "balanced", "label": "自动优选", "hint": "始终下发检测结果；低于目标时诚实降级，不回退全量"},
            {"value": "strict", "label": "严格优选", "hint": "始终使用优选结果；服务异常时仅以手动节点应急"},
        ],
    }


def public_subscription_enabled() -> bool:
    value = get_setting("public_subscription_enabled", "1").strip().lower()
    return value in {"1", "true", "yes", "on"}


def public_subscription_status() -> dict:
    enabled = public_subscription_enabled()
    return {
        "enabled": enabled,
        "label": "公开入口开启" if enabled else "仅会员链接",
        "detail": "任何人可访问 /clash、/v2ray 等公共订阅" if enabled else "公共订阅入口关闭，仅 /sub/<用户token>/... 可用",
        "token_enabled": bool(SUB_TOKEN),
    }


def return_test_host() -> str:
    return get_setting("return_test_host", RETURN_TEST_HOST).strip()


def return_test_port() -> int:
    value = get_setting("return_test_port", RETURN_TEST_PORT or "443").strip() or "443"
    try:
        port = int(value)
    except ValueError:
        return 443
    if not 1 <= port <= 65535:
        return 443
    return port


def return_test_target() -> tuple[str, int] | None:
    host = return_test_host()
    if not host:
        return None
    return host, return_test_port()


def current_admin_user() -> str:
    return get_setting("admin_user", ADMIN_USER)


def is_default_password() -> bool:
    password_hash = get_setting("admin_password_hash")
    return bool(password_hash and check_password_hash(password_hash, "admin"))


def valid_admin_login(username: str, password: str) -> bool:
    password_hash = get_setting("admin_password_hash")
    return secrets.compare_digest(username, current_admin_user()) and bool(password_hash) and check_password_hash(password_hash, password)


def update_admin_password(old_password: str, new_password: str) -> bool:
    if not valid_admin_login(current_admin_user(), old_password):
        return False
    set_setting("admin_password_hash", generate_password_hash(new_password))
    return True


def display_name(row: sqlite3.Row | dict) -> str:
    custom = row["display_name"] if "display_name" in row.keys() else ""
    return custom or row["name"] or "node"


def set_uri_fragment(raw: str, name: str) -> str:
    return raw.split("#", 1)[0] + "#" + quote(name, safe="")


def format_node_for_subscription(raw: str, name: str) -> str:
    if not name:
        return raw
    try:
        if raw.startswith("vmess://"):
            info = json.loads(b64decode_text(raw[8:]))
            info["ps"] = name
            return "vmess://" + b64encode_text(json.dumps(info, ensure_ascii=False, separators=(",", ":")))
        if raw.startswith(("ss://", "vless://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://")):
            return set_uri_fragment(raw, name)
    except Exception:
        return raw
    return raw


def load_node_items(enabled_only: bool = True) -> list[dict]:
    with db() as conn:
        sql = "SELECT * FROM nodes"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id"
        return [dict(row) for row in conn.execute(sql)]


def list_upstreams() -> list[dict]:
    with db() as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM upstreams ORDER BY id DESC")]
    for row in rows:
        row["source_label"] = "文件/粘贴" if row.get("source_type") == "file" else "链接"
        row["is_system_source"] = str(row.get("name") or "").strip() == SUBS_CHECK_IMPORT_NAME
        if row.get("source_type") == "url":
            parsed_url = urlparse(str(row.get("url") or ""))
            row["url_label"] = f"{parsed_url.netloc} · 已配置链接" if parsed_url.netloc else "链接未配置"
        else:
            row["url_label"] = "保存在本机的导入内容"
        row["interval_label"] = format_minutes(row.get("update_interval_minutes") or 60)
        raw_count = row.get("last_raw_count") or row.get("last_count", 0)
        row["node_count_label"] = f"{row.get('last_count', 0)} / {raw_count}"
        row["filter_label"] = "只保留节点" if row.get("only_nodes", 1) else "不过滤"
        row["last_checked_label"] = relative_time(row.get("last_checked_at", ""))
        row["last_updated_label"] = relative_time(row.get("last_synced_at", ""))
        row["verify_status"] = "同步失败" if row.get("last_status") == "同步失败" else ("正常" if row.get("last_count", 0) else "待验证")
        row["verify_tone"] = "danger" if row["verify_status"] == "同步失败" else ("ok" if row["verify_status"] == "正常" else "warn")
        row["verify_label"] = f"原始 {raw_count} · 入库 {row.get('last_count', 0)}"
    return rows


def format_minutes(minutes: int) -> str:
    minutes = max(1, int(minutes or 60))
    hours, remain = divmod(minutes, 60)
    if hours:
        return f"{hours} 小时 {remain} 分钟"
    return f"{remain} 分钟"


def relative_time(value: str) -> str:
    if not value:
        return "从未"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    seconds = max(0, int((datetime.now() - dt).total_seconds()))
    if seconds < 60:
        return "刚刚"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} 分钟前"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} 小时前"
    return f"{hours // 24} 天前"


def get_upstream(upstream_id: int) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM upstreams WHERE id = ?", (upstream_id,)).fetchone()


def fetch_url_text(url: str, timeout: int | float = 20) -> str:
    req = Request(
        url,
        headers={
            "User-Agent": UPSTREAM_USER_AGENT or "ClashMetaForAndroid/2.11.13",
            "Accept": "text/plain, application/yaml, application/octet-stream, */*",
        },
    )
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read(5 * 1024 * 1024)
    return data.decode("utf-8", errors="replace")


def subs_check_output_url() -> str:
    path = SUBS_CHECK_OUTPUT_PATH
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{SUBS_CHECK_BASE_URL}/{path.lstrip('/')}"


def subs_check_public_admin_url() -> str:
    if not SUBS_CHECK_PUBLIC_URL:
        return ""
    return f"{SUBS_CHECK_PUBLIC_URL}/admin"


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_subs_check_config() -> dict:
    if not SUBS_CHECK_CONFIG_FILE.exists():
        return {}
    try:
        data = yaml.safe_load(SUBS_CHECK_CONFIG_FILE.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def write_subs_check_config(config: dict) -> None:
    SUBS_CHECK_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
    SUBS_CHECK_CONFIG_FILE.write_text(text, encoding="utf-8")


def subs_check_source_tag(config: dict) -> str:
    for item in as_list(config.get("sub-urls")):
        text = str(item)
        if "#sub-service" in text:
            continue
        if "#" in text:
            return unquote(text.rsplit("#", 1)[1]).strip()
    return "iguang-sub"


def set_subs_check_source_tag(config: dict, tag: str) -> None:
    tag = re.sub(r"[\r\n#]+", " ", (tag or "").strip())
    tag = re.sub(r"\s+", "-", tag).strip("-")[:48] or "ray-sub"
    source_url = "http://sub-service:8001/internal/subs-check/source"
    updated = []
    replaced = False
    for item in as_list(config.get("sub-urls")):
        text = str(item).strip()
        if not text:
            continue
        base = text.split("#", 1)[0]
        if base == source_url:
            updated.append(f"{source_url}#{quote(tag, safe='')}")
            replaced = True
        else:
            updated.append(text)
    if not replaced:
        updated.insert(0, f"{source_url}#{quote(tag, safe='')}")
    config["sub-urls"] = updated


def subs_check_config_summary() -> dict:
    config = load_subs_check_config()
    filters = [str(item) for item in as_list(config.get("filter")) if str(item).strip()]
    node_types = [str(item) for item in as_list(config.get("node-type")) if str(item).strip()]
    platforms = [str(item) for item in as_list(config.get("platforms")) if str(item).strip()]
    recipients = [str(item) for item in as_list(config.get("recipient-url")) if str(item).strip()]
    return {
        "path": str(SUBS_CHECK_CONFIG_FILE),
        "exists": SUBS_CHECK_CONFIG_FILE.exists(),
        "writable": SUBS_CHECK_CONFIG_FILE.parent.exists() and os.access(SUBS_CHECK_CONFIG_FILE.parent, os.W_OK),
        "media_check": bool(config.get("media-check", False)),
        "platforms": platforms,
        "platform_options": ["iprisk", "youtube", "netflix", "openai", "gemini", "claude"],
        "node_types": node_types,
        "node_type_options": ["ss", "ssr", "vmess", "vless", "trojan", "hysteria2", "hy2", "tuic", "http", "https"],
        "filter_text": "\n".join(filters),
        "filter_count": len(filters),
        "success_rate": safe_int(config.get("success-rate"), 0),
        "keep_days": safe_int(config.get("keep-days"), 0),
        "check_interval": safe_int(config.get("check-interval"), 120),
        "min_speed": safe_int(config.get("min-speed"), 0),
        "concurrent": safe_int(config.get("concurrent"), 10),
        "media_concurrent": safe_int(config.get("media-concurrent"), 4),
        "speed_concurrent": safe_int(config.get("speed-concurrent"), 6),
        "sub_urls_get_ua": str(config.get("sub-urls-get-ua") or UPSTREAM_USER_AGENT or "ClashMetaForAndroid/2.11.13"),
        "source_tag": subs_check_source_tag(config),
        "apprise_api_server": str(config.get("apprise-api-server") or ""),
        "recipient_text": "\n".join(recipients),
        "recipient_count": len(recipients),
        "sub_store_enabled": bool(config.get("sub-store-path") or config.get("sub-store-sync-cron") or config.get("sub-store-produce-cron")),
        "dns_enabled": bool((config.get("dns") or {}).get("enable")) if isinstance(config.get("dns"), dict) else False,
    }


def subs_check_api_headers() -> dict:
    headers = {"Accept": "application/json"}
    if SUBS_CHECK_API_KEY:
        headers["X-API-Key"] = SUBS_CHECK_API_KEY
    return headers


def subs_check_api_request(path: str, method: str = "GET", payload: dict | None = None, timeout: int | float = 12) -> dict:
    if not SUBS_CHECK_API_KEY:
        raise ValueError("未配置 SUBS_CHECK_API_KEY，无法调用 subs-check 控制 API")
    url = f"{SUBS_CHECK_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    data = None
    headers = subs_check_api_headers()
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read(1024 * 1024)
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {"raw": raw.decode("utf-8", errors="replace")}


def subs_check_api_status(timeout: int | float = 3) -> dict:
    try:
        payload = subs_check_api_request("/api/status", timeout=timeout)
        pipeline = payload.get("pipeline") if isinstance(payload.get("pipeline"), dict) else {}
        return {
            "ok": True,
            "message": "API 可用",
            "checking": bool(payload.get("checking")),
            "proxy_count": safe_int(payload.get("proxyCount") or pipeline.get("total")),
            "available": safe_int(payload.get("available") or pipeline.get("alivePass")),
            "progress": safe_int(payload.get("progress") or pipeline.get("aliveDone")),
            "media_done": safe_int(pipeline.get("mediaDone")),
            "filter_pass": safe_int(pipeline.get("filterPass")),
            "speed_done": safe_int(pipeline.get("speedDone")),
            "speed_pass": safe_int(pipeline.get("speedPass")),
            "has_speed_test": bool(payload.get("hasSpeedTest")),
        }
    except Exception as exc:
        return {
            "ok": False,
            "message": str(exc)[:180],
            "checking": False,
            "proxy_count": 0,
            "available": 0,
            "progress": 0,
            "media_done": 0,
            "filter_pass": 0,
            "speed_done": 0,
            "speed_pass": 0,
            "has_speed_test": False,
        }


def subs_check_api_logs(limit: int = 80, timeout: int | float = 3) -> list[str]:
    try:
        payload = subs_check_api_request("/api/logs", timeout=timeout)
        logs = payload.get("logs") if isinstance(payload, dict) else []
        if not isinstance(logs, list):
            return []
        return [str(line) for line in logs[-limit:]]
    except Exception as exc:
        return [f"读取 subs-check 日志失败：{str(exc)[:180]}"]


def record_subs_check_run(action: str, status: str, message: str, node_count: int = 0, checking: bool = False) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO subs_check_runs(action, status, message, node_count, checking, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (action, status, message[:500], max(0, int(node_count or 0)), 1 if checking else 0, now),
        )


def list_subs_check_runs(limit: int = 8) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM subs_check_runs ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 50)),),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["created_label"] = relative_time(item.get("created_at", ""))
        item["tone"] = "ok" if item.get("status") in {"成功", "已触发", "导入成功"} else "danger" if item.get("status") in {"失败", "异常"} else "warn"
        result.append(item)
    return result


def save_subs_check_config_from_form(form) -> dict:
    config = load_subs_check_config()
    if not config:
        config = {
            "print-progress": True,
            "concurrent": 10,
            "media-concurrent": 4,
            "speed-concurrent": 6,
            "check-interval": 120,
            "timeout": 5000,
            "listen-port": ":8199",
            "rename-node": True,
            "filter": [],
            "media-check": False,
            "platforms": ["iprisk", "youtube", "netflix", "openai", "gemini", "claude"],
            "node-type": ["ss", "ssr", "vmess", "vless", "trojan", "hysteria2", "hy2", "tuic", "http", "https"],
            "output-dir": "/app/output",
            "sub-urls-get-ua": UPSTREAM_USER_AGENT or "ClashMetaForAndroid/2.11.13",
            "success-rate": 0,
            "sub-urls": ["http://sub-service:8001/internal/subs-check/source#ray-sub"],
        }
    config["media-check"] = form.get("media_check") == "1"
    config["filter"] = clean_lines(form.get("filter_text", ""))
    config["node-type"] = [item for item in form.getlist("node_types") if item]
    config["platforms"] = [item for item in form.getlist("platforms") if item]
    config["success-rate"] = max(0, min(100, safe_int(form.get("success_rate"), 0)))
    config["keep-days"] = max(0, safe_int(form.get("keep_days"), 0))
    config["check-interval"] = max(1, safe_int(form.get("check_interval"), 120))
    config["min-speed"] = max(0, safe_int(form.get("min_speed"), 0))
    config["concurrent"] = max(1, min(20, safe_int(form.get("concurrent"), 10)))
    config["media-concurrent"] = max(1, min(10, safe_int(form.get("media_concurrent"), 4)))
    config["speed-concurrent"] = max(1, min(10, safe_int(form.get("speed_concurrent"), 6)))
    config["sub-urls-get-ua"] = form.get("sub_urls_get_ua", "").strip() or UPSTREAM_USER_AGENT or "ClashMetaForAndroid/2.11.13"
    set_subs_check_source_tag(config, form.get("source_tag", "ray-sub"))
    config["apprise-api-server"] = form.get("apprise_api_server", "").strip()
    config["recipient-url"] = clean_lines(form.get("recipient_text", ""))
    write_subs_check_config(config)
    return config


def subs_check_quality_source_assets() -> list[dict]:
    assets: list[dict] = []
    for item in load_node_items(enabled_only=True):
        assets.append({
            "asset_key": f"manual:{item['id']}",
            "raw": item.get("raw", ""),
            "clash_proxy": None,
        })
    for item in load_upstream_node_items(enabled_only=True):
        if str(item.get("upstream_name") or "").strip() == SUBS_CHECK_IMPORT_NAME:
            continue
        assets.append({
            "asset_key": upstream_asset_key(item),
            "raw": item.get("raw", ""),
            "clash_proxy_json": item.get("clash_proxy_json", ""),
        })
    for asset in assets:
        asset["identity_key"] = node_identity_key(asset)
    return assets


def subs_check_output_marker(text: str) -> tuple[str, str, str]:
    output_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    output_name = Path(urlparse(SUBS_CHECK_OUTPUT_PATH).path).name or "all.yaml"
    output_file = SUBS_CHECK_OUTPUT_DIR / output_name
    if output_file.exists():
        stat = output_file.stat()
        marker = f"file:{stat.st_mtime_ns}:{stat.st_size}:{output_hash}"
        checked_at = datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds")
    else:
        # Without a mounted output file, identical responses cannot prove a new check round.
        marker = f"remote:{output_hash}"
        checked_at = datetime.now().isoformat(timespec="seconds")
    return hashlib.sha256(marker.encode("utf-8")).hexdigest(), output_hash, checked_at


def capture_subs_check_quality_round(text: str, output_items: list[dict]) -> bool:
    run_key, output_hash, checked_at = subs_check_output_marker(text)
    with db() as conn:
        if conn.execute("SELECT 1 FROM subs_check_quality_runs WHERE run_key = ?", (run_key,)).fetchone():
            return False

    output_by_identity: dict[str, dict] = {}
    for item in output_items:
        identity_key = node_identity_key(item)
        if identity_key and identity_key not in output_by_identity:
            output_by_identity[identity_key] = item
    assets = subs_check_quality_source_assets()
    asset_identities = {asset.get("identity_key") for asset in assets if asset.get("identity_key")}
    matched_output_count = len(asset_identities.intersection(output_by_identity))
    config = load_subs_check_config()
    min_speed = safe_int(config.get("min-speed"), 0) if isinstance(config, dict) else 0

    try:
        with db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO subs_check_quality_runs(
                    run_key, output_hash, input_count, output_count, matched_output_count, min_speed_kbps, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_key, output_hash, len(assets), len(output_items), matched_output_count, min_speed, checked_at),
            )
            run_id = int(cursor.lastrowid)
            for asset in assets:
                identity_key = asset.get("identity_key") or ""
                output_item = output_by_identity.get(identity_key) if identity_key else None
                output_name = str((output_item or {}).get("name") or "")
                metadata = extract_subs_check_metadata(output_name) if output_item else {}
                conn.execute(
                    """
                    INSERT INTO node_quality_observations(
                        run_id, asset_key, identity_key, passed, output_name, speed_label, checked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        asset["asset_key"],
                        identity_key,
                        1 if output_item else 0,
                        output_name,
                        metadata.get("speed_label", ""),
                        checked_at,
                    ),
                )
            cutoff = (datetime.now() - timedelta(days=30)).isoformat(timespec="seconds")
            conn.execute("DELETE FROM subs_check_quality_runs WHERE checked_at < ?", (cutoff,))
        return True
    except sqlite3.IntegrityError:
        return False


def list_node_quality_rounds(limit_runs: int = 3) -> tuple[dict[str, dict], list[dict]]:
    limit_runs = max(1, min(limit_runs, 10))
    with db() as conn:
        run_rows = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM subs_check_quality_runs ORDER BY checked_at DESC, id DESC LIMIT ?",
                (limit_runs,),
            )
        ]
        if not run_rows:
            return {}, []
        run_ids = [row["id"] for row in run_rows]
        placeholders = ",".join("?" for _ in run_ids)
        observations = [
            dict(row)
            for row in conn.execute(
                f"SELECT * FROM node_quality_observations WHERE run_id IN ({placeholders})",
                run_ids,
            )
        ]
    run_order = {run_id: index for index, run_id in enumerate(run_ids)}
    grouped: dict[str, list[dict]] = {}
    for row in observations:
        grouped.setdefault(row["asset_key"], []).append(row)
    result: dict[str, dict] = {}
    for asset_key, rows in grouped.items():
        rows.sort(key=lambda row: run_order.get(row["run_id"], 999))
        passed_count = sum(1 for row in rows if row.get("passed"))
        rounds_count = len(rows)
        latest = next((row for row in rows if row["run_id"] == run_ids[0]), None)
        if rounds_count >= 3:
            if passed_count == 3:
                stability_label, stability_tone = "连续稳定", "ok"
            elif passed_count == 2:
                stability_label, stability_tone = "间歇可用", "warn"
            elif passed_count == 1:
                stability_label, stability_tone = "偶发通过", "danger"
            else:
                stability_label, stability_tone = "连续未入选", "danger"
            rounds_label = f"{passed_count}/3 · {stability_label}"
        else:
            stability_label, stability_tone = "样本积累中", "neutral"
            rounds_label = f"{passed_count}/{rounds_count} · 样本积累中"
        result[asset_key] = {
            "rounds_count": rounds_count,
            "passed_count": passed_count,
            "latest_passed": bool(latest and latest.get("passed")),
            "rounds_label": rounds_label,
            "stability_label": stability_label,
            "stability_tone": stability_tone,
            "last_output_name": str((latest or {}).get("output_name") or ""),
            "last_speed_label": str((latest or {}).get("speed_label") or ""),
            "marks": ["通过" if row.get("passed") else "未入选" for row in rows],
        }
    return result, run_rows


def subs_check_quality_summary() -> dict:
    node_rounds, runs = list_node_quality_rounds(3)
    if not runs:
        return {
            "runs_count": 0,
            "current_l3": 0,
            "current_l3_assets": 0,
            "stable_3": 0,
            "intermittent_2": 0,
            "fragile_1": 0,
            "not_selected": 0,
            "input_count": 0,
            "output_count": 0,
            "matched_output_count": 0,
            "match_percent": 0,
            "checked_at": "",
            "checked_label": "尚未形成检测轮次",
            "sample_label": "等待首次自动检测",
        }
    latest = runs[0]
    full_sample = len(runs) >= 3
    return {
        "runs_count": len(runs),
        "current_l3": safe_int(latest.get("matched_output_count")),
        "current_l3_assets": sum(1 for item in node_rounds.values() if item.get("latest_passed")),
        "stable_3": sum(1 for item in node_rounds.values() if item.get("rounds_count") >= 3 and item.get("passed_count") == 3),
        "intermittent_2": sum(1 for item in node_rounds.values() if item.get("rounds_count") >= 3 and item.get("passed_count") == 2),
        "fragile_1": sum(1 for item in node_rounds.values() if item.get("rounds_count") >= 3 and item.get("passed_count") == 1),
        "not_selected": sum(1 for item in node_rounds.values() if item.get("rounds_count") >= 3 and item.get("passed_count") == 0),
        "input_count": safe_int(latest.get("input_count")),
        "output_count": safe_int(latest.get("output_count")),
        "matched_output_count": safe_int(latest.get("matched_output_count")),
        "match_percent": percent(safe_int(latest.get("matched_output_count")), safe_int(latest.get("output_count"))),
        "checked_at": latest.get("checked_at", ""),
        "checked_label": relative_time(latest.get("checked_at", "")),
        "sample_label": "最近三轮" if full_sample else f"已积累 {len(runs)}/3 轮",
    }


def subs_check_status(timeout: int | float = 3) -> dict:
    output_url = subs_check_output_url()
    result = {
        "enabled": bool(SUBS_CHECK_BASE_URL),
        "base_url": SUBS_CHECK_BASE_URL,
        "public_url": SUBS_CHECK_PUBLIC_URL,
        "admin_url": subs_check_public_admin_url(),
        "output_path": SUBS_CHECK_OUTPUT_PATH,
        "output_url": output_url,
        "ok": False,
        "node_count": 0,
        "message": "未检测",
        "sample": [],
        "quality": subs_check_quality_summary(),
    }
    if not result["enabled"]:
        result["message"] = "未配置 SUBS_CHECK_BASE_URL"
        return result
    try:
        text = fetch_url_text(output_url, timeout=timeout)
        output_items = parse_subscription_items_from_text(text)
        nodes = [item["raw"] for item in output_items]
        capture_subs_check_quality_round(text, output_items)
        result["ok"] = True
        result["node_count"] = len(nodes)
        result["message"] = f"可读取 {len(nodes)} 个节点"
        result["sample"] = [parse_node(raw)["name"] for raw in nodes[:5]]
        result["quality"] = subs_check_quality_summary()
    except Exception as exc:
        result["message"] = str(exc)[:200]
    return result


def subscription_engine_state(status_timeout: int | float = 3) -> dict:
    local_count = len(load_subscription_items(enabled_only=True))
    manual_count = len(load_manual_subscription_items(enabled_only=True))
    subs = subs_check_status(timeout=status_timeout)
    mode = subscription_engine_mode()
    min_output_nodes = subs_check_min_output_nodes()
    use_subs = False
    reason = ""
    reason_code = "local"
    active = "local"
    output_count = local_count
    output_status = "local"
    if mode == "local":
        reason = "管理员已明确选择全量节点池"
        reason_code = "local_mode"
    elif not SUBS_CHECK_SUBSCRIPTION_ENABLED:
        active = "manual" if manual_count else "unavailable"
        output_count = manual_count
        output_status = "emergency" if manual_count else "unavailable"
        reason = "subs-check 输出未启用，仅下发手动应急池" if manual_count else "subs-check 输出未启用，且没有手动应急节点"
        reason_code = "subs_check_disabled"
    elif not subs["ok"]:
        active = "manual" if manual_count else "unavailable"
        output_count = manual_count
        output_status = "emergency" if manual_count else "unavailable"
        reason = f"subs-check 不可用，仅下发手动应急池：{subs['message']}" if manual_count else f"subs-check 不可用：{subs['message']}"
        reason_code = "subs_check_unavailable"
    elif subs["node_count"] <= 0:
        active = "manual" if manual_count else "unavailable"
        output_count = manual_count
        output_status = "emergency" if manual_count else "unavailable"
        reason = "优选池为空，仅下发手动应急池" if manual_count else "优选池为空，且没有手动应急节点"
        reason_code = "subs_check_empty"
    elif mode == "strict":
        use_subs = True
        active = "subs-check"
        output_count = subs["node_count"]
        output_status = "normal" if subs["node_count"] >= min_output_nodes else "degraded"
        reason = "严格使用 subs-check 优选输出"
        reason_code = "strict_subs_check"
    elif subs["node_count"] >= min_output_nodes:
        use_subs = True
        active = "subs-check"
        output_count = subs["node_count"]
        output_status = "normal"
        reason = f"subs-check 达到目标数量 {min_output_nodes}"
        reason_code = "subs_check_threshold_met"
    else:
        use_subs = True
        active = "subs-check"
        output_count = subs["node_count"]
        output_status = "degraded"
        reason = f"优选池仅 {subs['node_count']} 个，低于目标 {min_output_nodes}；保持优选输出，不回退全量"
        reason_code = "subs_check_below_threshold"
    active_labels = {
        "subs-check": "优选输出",
        "manual": "手动应急",
        "local": "全量输出",
        "unavailable": "暂无输出",
    }
    status_tones = {"normal": "ok", "degraded": "warn", "emergency": "warn", "local": "neutral", "unavailable": "danger"}
    status_details = {
        "normal": "正在使用检测后的优选结果",
        "degraded": "优选节点偏少，已诚实降级且未混入未检节点",
        "emergency": "优选服务不可用，仅使用手动节点应急",
        "local": "管理员已明确选择完整资产池",
        "unavailable": "当前没有可安全下发的节点",
    }
    return {
        "mode": mode,
        "active": active,
        "active_label": active_labels[active],
        "status": output_status,
        "status_tone": status_tones[output_status],
        "status_detail": status_details[output_status],
        "degraded": output_status in {"degraded", "emergency"},
        "use_subs_check": use_subs,
        "default_output_count": output_count,
        "default_output_label": (
            f"优选 {output_count} 个（节点紧张）" if output_status == "degraded"
            else f"手动应急 {output_count} 个" if output_status == "emergency"
            else f"暂无安全节点" if output_status == "unavailable"
            else f"优选 {output_count} 个" if active == "subs-check"
            else f"全量 {output_count} 个"
        ),
        "asset_pool_count": local_count,
        "manual_pool_count": manual_count,
        "reason": reason,
        "reason_code": reason_code,
        "local_count": local_count,
        "subs_check": subs,
        "quality": subs.get("quality") or subs_check_quality_summary(),
        "min_output_nodes": min_output_nodes,
        "settings": subscription_engine_settings(),
        "strict_url": f"{DINGYUE_PATH}/best/clash",
    }


def upstream_source_text(upstream: sqlite3.Row | dict) -> str:
    source_type = upstream["source_type"] if "source_type" in upstream.keys() else "url"
    if source_type == "file":
        content = upstream["content"] if "content" in upstream.keys() else ""
        if not content.strip():
            raise ValueError("上传内容为空")
        return content
    return fetch_url_text(upstream["url"])


def apply_upstream_prefix(raw: str, prefix: str) -> str:
    prefix = prefix.strip()
    if not prefix:
        return raw
    parsed = parse_node(raw)
    name = f"{prefix} {parsed['name']}".strip()
    return format_node_for_subscription(raw, name)


INFO_NODE_KEYWORDS = [
    "剩余流量", "套餐到期", "官网", "公告", "建议", "提示", "通知", "更新订阅", "防失联",
    "失联", "流量", "到期", "过期", "重置", "订阅", "客服", "群", "频道", "网址",
    "traffic", "expire", "expired", "subscription", "official", "notice", "剩余", "用量",
]


REAL_NODE_HINTS = [
    "香港", "台湾", "日本", "新加坡", "美国", "韩国", "英国", "德国", "法国", "印度",
    "港", "台", "日", "新", "美", "韩", "sg", "jp", "hk", "tw", "us", "kr",
    "iplc", "iepl", "家宽", "专线", "中转", "原生", "vless", "trojan", "hysteria", "倍率", "x",
]


def decoded_for_filter(raw: str, name: str = "") -> str:
    return " ".join([raw, unquote(raw), name, unquote(name)]).lower()


def upstream_name_has_route_hint(name: str) -> bool:
    normalized = unquote(name or "").strip().lower()
    if not normalized:
        return False
    strong_hints = [
        "香港", "台湾", "日本", "新加坡", "美国", "韩国", "英国", "德国", "法国", "印度",
        "iplc", "iepl", "家宽", "专线", "中转", "原生", "vless", "trojan", "hysteria",
    ]
    if any(hint in normalized for hint in strong_hints):
        return True
    return bool(
        re.search(
            r"(?:^|[\s|_\-])(?:cdn|node|line|线路|节点|route|edge)[\s_\-]*\d+(?:$|[\s|_\-])",
            normalized,
        )
        or re.search(r"(?:^|[\s|_\-])(?:hk|tw|jp|sg|us|kr|uk|de|fr|in)[\s_\-]*\d*(?:$|[\s|_\-])", normalized)
        or re.search(r"[\U0001F1E6-\U0001F1FF]{2}", normalized)
    )


def is_real_upstream_node(raw: str, display_name: str = "") -> bool:
    item = parse_node(raw)
    if item.get("protocol") == "unknown":
        return False
    endpoint = node_endpoint(raw)
    if not endpoint:
        return False
    host, port = endpoint
    if not (host and port):
        return False
    name = display_name or item.get("name") or ""
    normalized_name = unquote(name).strip().lower()
    has_info_keyword = any(keyword.lower() in normalized_name for keyword in INFO_NODE_KEYWORDS)
    if has_info_keyword and not upstream_name_has_route_hint(normalized_name):
        return False
    return True


def filter_upstream_nodes(nodes: list[str], only_nodes: bool = True) -> list[str]:
    if not only_nodes:
        return nodes
    return [node for node in nodes if is_real_upstream_node(node)]


def filter_upstream_node_items(items: list[dict], only_nodes: bool = True) -> list[dict]:
    if not only_nodes:
        return items
    return [
        item
        for item in items
        if is_real_upstream_node(item.get("raw", ""), item.get("name", ""))
    ]


def apply_upstream_prefix_item(item: dict, prefix: str) -> dict:
    prefix = prefix.strip()
    if not prefix:
        return item
    renamed = dict(item)
    current_name = renamed.get("name") or parse_node(renamed.get("raw", ""))["name"]
    name = f"{prefix} {current_name}".strip()
    renamed["raw"] = format_node_for_subscription(renamed.get("raw", ""), name)
    renamed["name"] = name
    clash_proxy = normalize_clash_proxy(renamed.get("clash_proxy"))
    if clash_proxy:
        clash_proxy["name"] = name
        renamed["clash_proxy"] = clash_proxy
    return renamed


def sync_upstream(upstream_id: int) -> tuple[bool, str, int]:
    upstream = get_upstream(upstream_id)
    if not upstream:
        return False, "订阅不存在", 0
    now = datetime.now().isoformat(timespec="seconds")
    try:
        text = upstream_source_text(upstream)
        parsed_items = parse_subscription_items_from_text(text)
        parsed_nodes = [item["raw"] for item in parsed_items]
        parse_note = upstream_parse_note(text, len(parsed_items))
        only_nodes = bool(upstream["only_nodes"]) if "only_nodes" in upstream.keys() else True
        items = filter_upstream_node_items(parsed_items, only_nodes=only_nodes)
        items = [apply_upstream_prefix_item(item, upstream["prefix"]) for item in items]
        if not items:
            if parsed_items and only_nodes:
                raise ValueError(f"已解析 {len(parsed_items)} 个节点，但全部被“只保留真实节点”规则过滤")
            raise ValueError("没有解析到支持的节点")
        with db() as conn:
            conn.execute("DELETE FROM upstream_nodes WHERE upstream_id = ?", (upstream_id,))
            for item in items:
                parsed = parse_node(item["raw"])
                clash_proxy_json = json.dumps(item.get("clash_proxy"), ensure_ascii=False, separators=(",", ":")) if item.get("clash_proxy") else ""
                conn.execute(
                    "INSERT OR IGNORE INTO upstream_nodes(upstream_id, raw, clash_proxy_json, protocol, name, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (upstream_id, parsed["raw"], clash_proxy_json, parsed["protocol"], item.get("name") or parsed["name"], now),
                )
            conn.execute(
                """
                UPDATE upstreams
                SET last_status = '同步成功', last_count = ?, last_raw_count = ?, last_checked_at = ?, last_synced_at = ?, last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                (len(items), len(parsed_items), now, now, parse_note, now, upstream_id),
            )
        return True, parse_note or "同步成功", len(items)
    except Exception as exc:
        message = str(exc)[:300]
        with db() as conn:
            conn.execute(
                "UPDATE upstreams SET last_status = '同步失败', last_checked_at = ?, last_error = ?, updated_at = ? WHERE id = ?",
                (now, message, now, upstream_id),
            )
        return False, message, 0


def upsert_subs_check_upstream() -> int:
    now = datetime.now().isoformat(timespec="seconds")
    url = subs_check_output_url()
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM upstreams WHERE url = ? OR name = ? ORDER BY id LIMIT 1",
            (url, SUBS_CHECK_IMPORT_NAME),
        ).fetchone()
        if row:
            upstream_id = int(row["id"])
            conn.execute(
                """
                UPDATE upstreams
                SET name = ?, url = ?, enabled = 1, prefix = '', source_type = 'url', content = '',
                    update_interval_minutes = 120, only_nodes = 1, updated_at = ?
                WHERE id = ?
                """,
                (SUBS_CHECK_IMPORT_NAME, url, now, upstream_id),
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO upstreams(name, url, enabled, prefix, source_type, content, update_interval_minutes, only_nodes, created_at, updated_at)
                VALUES (?, ?, 1, '', 'url', '', 120, 1, ?, ?)
                """,
                (SUBS_CHECK_IMPORT_NAME, url, now, now),
            )
            upstream_id = int(cur.lastrowid)
    return upstream_id


def mark_upstream_nodes_proxy_ok(upstream_id: int) -> int:
    rows = [row for row in load_upstream_node_items(enabled_only=False) if int(row.get("upstream_id") or 0) == int(upstream_id)]
    for row in rows:
        update_node_check(upstream_asset_key(row), None, "proxy_ok")
    return len(rows)


MEDIA_LABEL_PATTERNS = [
    ("OpenAI", re.compile(r"(GPT\+|GPT⁺|GPT|OpenAI)", re.I)),
    ("Netflix", re.compile(r"(NF-[A-Z]{2}|NF|Netflix)", re.I)),
    ("YouTube", re.compile(r"(YT-[A-Z]{2}|YT|YouTube)", re.I)),
    ("Gemini", re.compile(r"(GM|Gemini)", re.I)),
    ("Claude", re.compile(r"(CL-[A-Z]{2}|CL|Claude)", re.I)),
    ("Disney+", re.compile(r"(D\+|Disney)", re.I)),
    ("Spotify", re.compile(r"(SP-[A-Z]{2}|SP|Spotify)", re.I)),
]


def extract_subs_check_metadata(name: str) -> dict:
    text = str(name or "")
    media = [label for label, pattern in MEDIA_LABEL_PATTERNS if pattern.search(text)]
    risk_match = re.search(r"(?<!\d)(100|[0-9]{1,2})%(?!\d)", text)
    speed_match = re.search(r"(\d+(?:\.\d+)?)\s*(KB/s|MB/s|GB/s|Kbps|Mbps|Gbps)", text, re.I)
    return {
        "subs_check_name": text,
        "media": media,
        "media_json": json.dumps(media, ensure_ascii=False, separators=(",", ":")),
        "ip_risk": f"{risk_match.group(1)}%" if risk_match else "",
        "speed_label": f"{speed_match.group(1)} {speed_match.group(2)}" if speed_match else "",
    }


def upsert_node_metadata(asset_key: str, metadata: dict, source: str = "subs-check") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO node_metadata(asset_key, source, subs_check_name, speed_label, ip_risk, media_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_key) DO UPDATE SET
                source = excluded.source,
                subs_check_name = excluded.subs_check_name,
                speed_label = excluded.speed_label,
                ip_risk = excluded.ip_risk,
                media_json = excluded.media_json,
                updated_at = excluded.updated_at
            """,
            (
                asset_key,
                source,
                metadata.get("subs_check_name", ""),
                metadata.get("speed_label", ""),
                metadata.get("ip_risk", ""),
                metadata.get("media_json", "[]"),
                now,
            ),
        )


def list_node_metadata() -> dict[str, dict]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM node_metadata").fetchall()
    result = {}
    for row in rows:
        item = dict(row)
        try:
            item["media"] = json.loads(item.get("media_json") or "[]")
        except Exception:
            item["media"] = []
        item["updated_label"] = relative_time(item.get("updated_at") or "") if item.get("updated_at") else "未更新"
        result[item["asset_key"]] = item
    return result


def enrich_subs_check_upstream_metadata(upstream_id: int) -> int:
    rows = [row for row in load_upstream_node_items(enabled_only=False) if int(row.get("upstream_id") or 0) == int(upstream_id)]
    count = 0
    for row in rows:
        asset_key = upstream_asset_key(row)
        metadata = extract_subs_check_metadata(row.get("name") or parse_node(row.get("raw", ""))["name"])
        upsert_node_metadata(asset_key, metadata)
        count += 1
    return count


def sync_enabled_upstreams() -> tuple[int, int]:
    ok = 0
    total = 0
    for upstream in list_upstreams():
        if not upstream["enabled"]:
            continue
        total += 1
        success, _message, _count = sync_upstream(upstream["id"])
        if success:
            ok += 1
    return ok, total


def load_upstream_nodes(enabled_only: bool = True) -> list[str]:
    rows = load_upstream_node_items(enabled_only=enabled_only)
    checks = list_node_checks() if FILTER_FAILED_UPSTREAM_NODES else {}
    result = []
    for row in rows:
        asset_key = upstream_asset_key(row)
        status = checks.get(asset_key, {}).get("status", "")
        if FILTER_FAILED_UPSTREAM_NODES and not upstream_check_allows_subscription(status):
            continue
        result.append(row["raw"])
    return result


def load_upstream_node_items(enabled_only: bool = True) -> list[dict]:
    with db() as conn:
        sql = """
            SELECT
                upstream_nodes.id,
                upstream_nodes.upstream_id,
                upstream_nodes.raw,
                upstream_nodes.clash_proxy_json,
                upstream_nodes.name,
                upstream_nodes.protocol,
                upstream_nodes.created_at,
                upstreams.name AS upstream_name,
                upstreams.enabled AS upstream_enabled,
                upstreams.last_status AS upstream_status
            FROM upstream_nodes
            JOIN upstreams ON upstreams.id = upstream_nodes.upstream_id
        """
        if enabled_only:
            sql += " WHERE upstreams.enabled = 1"
        sql += " ORDER BY upstreams.id, upstream_nodes.id"
        return [dict(row) for row in conn.execute(sql)]


def dedupe_node_items(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result: list[dict] = []
    for item in items:
        raw = item.get("raw", "")
        if not raw or raw in seen:
            continue
        seen.add(raw)
        result.append(item)
    return result


def add_nodes(nodes: list[str], make_backup: bool = True) -> tuple[int, int]:
    if make_backup:
        backup_current_nodes()
    now = datetime.now().isoformat(timespec="seconds")
    added = 0
    skipped = 0
    with db() as conn:
        for raw in nodes:
            item = parse_node(raw)
            try:
                conn.execute(
                    "INSERT INTO nodes(raw, protocol, name, enabled, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                    (item["raw"], item["protocol"], item["name"], now, now),
                )
                added += 1
            except sqlite3.IntegrityError:
                skipped += 1
    sync_nodes_file()
    return added, skipped


def replace_nodes(nodes: list[str]) -> int:
    backup_current_nodes()
    now = datetime.now().isoformat(timespec="seconds")
    seen: set[str] = set()
    saved = 0
    with db() as conn:
        previous = {
            row["raw"]: row
            for row in conn.execute(
                "SELECT raw, display_name, last_latency_ms, last_tested_at, test_status FROM nodes"
            )
        }
        conn.execute("DELETE FROM nodes")
        for raw in nodes:
            if raw in seen:
                continue
            seen.add(raw)
            saved += 1
            item = parse_node(raw)
            old = previous.get(raw)
            conn.execute(
                """
                INSERT INTO nodes(raw, protocol, name, display_name, enabled, last_latency_ms, last_tested_at, test_status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    item["raw"],
                    item["protocol"],
                    item["name"],
                    old["display_name"] if old else "",
                    old["last_latency_ms"] if old else None,
                    old["last_tested_at"] if old else None,
                    old["test_status"] if old else "未测速",
                    now,
                    now,
                ),
            )
    sync_nodes_file()
    return saved


def load_nodes(enabled_only: bool = True, renamed: bool = True) -> list[str]:
    items = load_node_items(enabled_only=enabled_only)
    if not renamed:
        manual = [item["raw"] for item in items]
    else:
        manual = [format_node_for_subscription(item["raw"], display_name(item)) for item in items]
    return dedupe_nodes(manual + load_upstream_nodes(enabled_only=enabled_only))


def load_manual_subscription_items(enabled_only: bool = True) -> list[dict]:
    return [
        {
            "raw": format_node_for_subscription(item["raw"], display_name(item)),
            "name": display_name(item),
            "protocol": item["protocol"],
            "source": "manual",
            "asset_key": f"manual:{item.get('id')}" if item.get("id") else "",
        }
        for item in load_node_items(enabled_only=enabled_only)
    ]


def load_subscription_items(enabled_only: bool = True) -> list[dict]:
    checks = list_node_checks() if FILTER_FAILED_UPSTREAM_NODES else {}
    manual = load_manual_subscription_items(enabled_only=enabled_only)
    upstream = []
    for item in load_upstream_node_items(enabled_only=enabled_only):
        asset_key = upstream_asset_key(item)
        check_status = checks.get(asset_key, {}).get("status", "")
        if FILTER_FAILED_UPSTREAM_NODES and not upstream_check_allows_subscription(check_status):
            continue
        clash_proxy = None
        if item.get("clash_proxy_json"):
            try:
                clash_proxy = json.loads(item["clash_proxy_json"])
            except Exception:
                clash_proxy = None
        upstream.append({
            "raw": item["raw"],
            "name": item.get("name") or parse_node(item["raw"])["name"],
            "protocol": item.get("protocol") or parse_node(item["raw"])["protocol"],
            "source": "upstream",
            "asset_key": asset_key,
            "check_status": check_status,
            "clash_proxy": clash_proxy,
        })
    return dedupe_node_items(manual + upstream)


def list_node_rows() -> list[sqlite3.Row]:
    with db() as conn:
        return list(conn.execute("SELECT * FROM nodes ORDER BY id DESC"))


def list_node_checks() -> dict[str, dict]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM node_checks").fetchall()
    return {row["asset_key"]: dict(row) for row in rows}


def list_node_check_history_stats(limit_per_asset: int = 20) -> dict[str, dict]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT asset_key, latency_ms, status, checked_at
            FROM node_check_history
            ORDER BY checked_at DESC, id DESC
            """
        ).fetchall()
    stats: dict[str, dict] = {}
    for row in rows:
        key = row["asset_key"]
        bucket = stats.setdefault(key, {"total": 0, "ok": 0, "failed": 0, "latencies": [], "last_failed_at": ""})
        if bucket["total"] >= limit_per_asset:
            continue
        status = str(row["status"] or "")
        bucket["total"] += 1
        if status in OK_NODE_CHECK_STATUSES:
            bucket["ok"] += 1
        elif status in FAILED_NODE_CHECK_STATUSES:
            bucket["failed"] += 1
            if not bucket["last_failed_at"]:
                bucket["last_failed_at"] = row["checked_at"]
        if row["latency_ms"] is not None:
            bucket["latencies"].append(int(row["latency_ms"]))
    for bucket in stats.values():
        total = bucket["total"] or 0
        bucket["success_rate"] = round(bucket["ok"] / total * 100) if total else None
        bucket["avg_latency_ms"] = round(sum(bucket["latencies"]) / len(bucket["latencies"])) if bucket["latencies"] else None
        bucket["success_rate_label"] = f"{bucket['success_rate']}%" if bucket["success_rate"] is not None else "暂无"
        bucket["avg_latency_label"] = f"{bucket['avg_latency_ms']} ms" if bucket["avg_latency_ms"] is not None else "-"
        bucket["last_failed_label"] = relative_time(bucket["last_failed_at"]) if bucket["last_failed_at"] else "无"
    return stats


def upstream_check_allows_subscription(status: str) -> bool:
    status = (status or "").strip()
    if status in FAILED_NODE_CHECK_STATUSES:
        return False
    if status in INCONCLUSIVE_NODE_CHECK_STATUSES:
        return True
    if UPSTREAM_REQUIRE_PROXY_OK:
        return status in OK_NODE_CHECK_STATUSES
    return True


def upstream_asset_key(row: dict) -> str:
    digest = hashlib.sha1(str(row.get("raw") or "").encode("utf-8")).hexdigest()[:12]
    return f"upstream:{row.get('upstream_id')}:{digest}"


def parse_iso_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def monitor_is_stale(monitor: dict | None) -> bool:
    if not monitor:
        return False
    timestamp = parse_iso_datetime(monitor.get("reported_at") or monitor.get("created_at") or "")
    if not timestamp:
        return True
    return datetime.now() - timestamp > timedelta(minutes=max(1, NODE_MONITOR_STALE_MINUTES))


def list_latest_node_monitors() -> dict[str, dict]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT nms.*
            FROM node_monitor_snapshots nms
            JOIN (
                SELECT asset_key, MAX(created_at) AS latest_at
                FROM node_monitor_snapshots
                GROUP BY asset_key
            ) latest
              ON latest.asset_key = nms.asset_key
             AND latest.latest_at = nms.created_at
            ORDER BY nms.id DESC
            """
        ).fetchall()
    result = {}
    for row in rows:
        item = dict(row)
        item["cpu_label"] = f"{item['cpu_percent']:.1f}%"
        item["memory_label"] = f"{item['memory_percent']:.1f}%"
        item["inbound_label"] = format_bps(item["inbound_bps"])
        item["outbound_label"] = format_bps(item["outbound_bps"])
        item["connections_label"] = compact_number(item["connections"])
        item["reported_label"] = relative_time(item["reported_at"] or item["created_at"])
        item["load_label"] = item.get("load_status") or "normal"
        item["is_stale"] = monitor_is_stale(item)
        item["fresh_label"] = "已过期" if item["is_stale"] else "新鲜"
        result[item["asset_key"]] = item
    return result


def latest_node_monitor_report() -> dict | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM node_monitor_snapshots ORDER BY created_at DESC, id DESC LIMIT 1").fetchone()
    if not row:
        return None
    item = dict(row)
    item["reported_label"] = relative_time(item["reported_at"] or item["created_at"])
    return item


def cleanup_node_monitor_snapshots(asset_key: str) -> None:
    retention_days = max(1, NODE_MONITOR_RETENTION_DAYS)
    max_per_asset = max(1, NODE_MONITOR_MAX_PER_ASSET)
    cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat(timespec="seconds")
    with db() as conn:
        conn.execute("DELETE FROM node_monitor_snapshots WHERE created_at < ?", (cutoff,))
        conn.execute(
            """
            DELETE FROM node_monitor_snapshots
            WHERE asset_key = ?
              AND id NOT IN (
                SELECT id
                FROM node_monitor_snapshots
                WHERE asset_key = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
              )
            """,
            (asset_key, asset_key, max_per_asset),
        )


def record_node_monitor(payload: dict) -> dict:
    asset_key = str(payload.get("asset_key") or "").strip()
    if not asset_key:
        raise ValueError("asset_key required")
    if not get_node_asset(asset_key):
        raise ValueError("node asset not found")
    now = datetime.now().isoformat(timespec="seconds")
    reported_at = str(payload.get("reported_at") or now).strip()
    try:
        datetime.fromisoformat(reported_at)
    except ValueError:
        reported_at = now
    row = {
        "asset_key": asset_key,
        "cpu_percent": clamp_percent(payload.get("cpu_percent")),
        "memory_percent": clamp_percent(payload.get("memory_percent")),
        "inbound_bps": max(0, safe_int(payload.get("inbound_bps"))),
        "outbound_bps": max(0, safe_int(payload.get("outbound_bps"))),
        "connections": max(0, safe_int(payload.get("connections"))),
        "load_status": str(payload.get("load_status") or "normal").strip()[:40],
        "reported_at": reported_at,
        "created_at": now,
    }
    with db() as conn:
        conn.execute(
            """
            INSERT INTO node_monitor_snapshots(
                asset_key, cpu_percent, memory_percent, inbound_bps, outbound_bps, connections, load_status, reported_at, created_at
            )
            VALUES (:asset_key, :cpu_percent, :memory_percent, :inbound_bps, :outbound_bps, :connections, :load_status, :reported_at, :created_at)
            """,
            row,
        )
    cleanup_node_monitor_snapshots(asset_key)
    return row


def update_node_check(asset_key: str, latency_ms: int | None, status: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO node_checks(asset_key, latency_ms, status, checked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(asset_key) DO UPDATE SET
                latency_ms = excluded.latency_ms,
                status = excluded.status,
                checked_at = excluded.checked_at
            """,
            (asset_key, latency_ms, status, now),
        )
        conn.execute(
            "INSERT INTO node_check_history(asset_key, latency_ms, status, checked_at) VALUES (?, ?, ?, ?)",
            (asset_key, latency_ms, status, now),
        )
        cutoff = (datetime.now() - timedelta(days=30)).isoformat(timespec="seconds")
        conn.execute("DELETE FROM node_check_history WHERE checked_at < ?", (cutoff,))


def update_node_entry_check(asset_key: str, latency_ms: int | None, status: str) -> None:
    """Store basic entry latency without overwriting real proxy verdicts."""
    existing = list_node_checks().get(asset_key, {})
    existing_status = str(existing.get("status") or "")
    if existing_status in OK_NODE_CHECK_STATUSES or existing_status in FAILED_NODE_CHECK_STATUSES:
        return
    update_node_check(asset_key, latency_ms, status)


def get_node_asset(asset_key: str) -> dict | None:
    for row in node_view_rows(include_upstream=True):
        if row.get("asset_key") == asset_key:
            return row
    return None


def safe_int(value, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def clamp_percent(value) -> float:
    return round(max(0.0, min(100.0, safe_float(value))), 1)


def compact_number(value: int | float) -> str:
    value = float(value or 0)
    if value >= 10000:
        return f"{value / 10000:.1f} 万"
    return f"{int(value):,}"


def format_bps(value: int | float) -> str:
    value = max(0.0, float(value or 0))
    if value >= 1024 * 1024 * 1024:
        return f"{value / 1024 / 1024 / 1024:.2f} Gbps"
    if value >= 1024 * 1024:
        return f"{value / 1024 / 1024:.2f} Mbps"
    if value >= 1024:
        return f"{value / 1024:.1f} Kbps"
    return f"{int(value)} bps"


def line_points(values: list[int | float], width: int = 560, height: int = 170) -> str:
    if not values:
        values = [0, 0]
    if len(values) == 1:
        values = [values[0], values[0]]
    top = max([float(value or 0) for value in values] + [1.0])
    coords = []
    for index, value in enumerate(values):
        x = width * index / (len(values) - 1)
        y = height - (float(value or 0) / top * (height - 12)) - 6
        coords.append(f"{x:.1f},{y:.1f}")
    return " ".join(coords)


def line_points_scaled(values: list[int | float], max_value: int | float, width: int = 560, height: int = 170) -> str:
    if not values:
        values = [0, 0]
    if len(values) == 1:
        values = [values[0], values[0]]
    top = max(float(max_value or 0), 1.0)
    coords = []
    for index, value in enumerate(values):
        x = width * index / (len(values) - 1)
        y = height - (float(value or 0) / top * (height - 12)) - 6
        coords.append(f"{x:.1f},{y:.1f}")
    return " ".join(coords)


COUNTRY_CONTINENTS = {
    "AF": "亚洲", "AL": "欧洲", "DZ": "非洲", "AS": "大洋洲", "AD": "欧洲", "AO": "非洲", "AI": "北美", "AQ": "其他",
    "AG": "北美", "AR": "南美", "AM": "亚洲", "AW": "北美", "AU": "大洋洲", "AT": "欧洲", "AZ": "亚洲",
    "BS": "北美", "BH": "亚洲", "BD": "亚洲", "BB": "北美", "BY": "欧洲", "BE": "欧洲", "BZ": "北美", "BJ": "非洲",
    "BM": "北美", "BT": "亚洲", "BO": "南美", "BA": "欧洲", "BW": "非洲", "BR": "南美", "BN": "亚洲", "BG": "欧洲",
    "BF": "非洲", "BI": "非洲", "KH": "亚洲", "CM": "非洲", "CA": "北美", "CV": "非洲", "KY": "北美", "CF": "非洲",
    "TD": "非洲", "CL": "南美", "CN": "亚洲", "CO": "南美", "KM": "非洲", "CG": "非洲", "CD": "非洲", "CR": "北美",
    "CI": "非洲", "HR": "欧洲", "CU": "北美", "CY": "亚洲", "CZ": "欧洲", "DK": "欧洲", "DJ": "非洲", "DM": "北美",
    "DO": "北美", "EC": "南美", "EG": "非洲", "SV": "北美", "GQ": "非洲", "ER": "非洲", "EE": "欧洲", "ET": "非洲",
    "FJ": "大洋洲", "FI": "欧洲", "FR": "欧洲", "GA": "非洲", "GM": "非洲", "GE": "亚洲", "DE": "欧洲", "GH": "非洲",
    "GR": "欧洲", "GD": "北美", "GT": "北美", "GN": "非洲", "GW": "非洲", "GY": "南美", "HT": "北美", "HN": "北美",
    "HK": "亚洲", "HU": "欧洲", "IS": "欧洲", "IN": "亚洲", "ID": "亚洲", "IR": "亚洲", "IQ": "亚洲", "IE": "欧洲",
    "IL": "亚洲", "IT": "欧洲", "JM": "北美", "JP": "亚洲", "JO": "亚洲", "KZ": "亚洲", "KE": "非洲", "KI": "大洋洲",
    "KP": "亚洲", "KR": "亚洲", "KW": "亚洲", "KG": "亚洲", "LA": "亚洲", "LV": "欧洲", "LB": "亚洲", "LS": "非洲",
    "LR": "非洲", "LY": "非洲", "LI": "欧洲", "LT": "欧洲", "LU": "欧洲", "MO": "亚洲", "MK": "欧洲", "MG": "非洲",
    "MW": "非洲", "MY": "亚洲", "MV": "亚洲", "ML": "非洲", "MT": "欧洲", "MH": "大洋洲", "MR": "非洲", "MU": "非洲",
    "MX": "北美", "FM": "大洋洲", "MD": "欧洲", "MC": "欧洲", "MN": "亚洲", "ME": "欧洲", "MA": "非洲", "MZ": "非洲",
    "MM": "亚洲", "NA": "非洲", "NR": "大洋洲", "NP": "亚洲", "NL": "欧洲", "NZ": "大洋洲", "NI": "北美", "NE": "非洲",
    "NG": "非洲", "NO": "欧洲", "OM": "亚洲", "PK": "亚洲", "PW": "大洋洲", "PS": "亚洲", "PA": "北美", "PG": "大洋洲",
    "PY": "南美", "PE": "南美", "PH": "亚洲", "PL": "欧洲", "PT": "欧洲", "PR": "北美", "QA": "亚洲", "RO": "欧洲",
    "RU": "欧洲", "RW": "非洲", "KN": "北美", "LC": "北美", "VC": "北美", "WS": "大洋洲", "SM": "欧洲", "ST": "非洲",
    "SA": "亚洲", "SN": "非洲", "RS": "欧洲", "SC": "非洲", "SL": "非洲", "SG": "亚洲", "SK": "欧洲", "SI": "欧洲",
    "SB": "大洋洲", "SO": "非洲", "ZA": "非洲", "SS": "非洲", "ES": "欧洲", "LK": "亚洲", "SD": "非洲", "SR": "南美",
    "SE": "欧洲", "CH": "欧洲", "SY": "亚洲", "TW": "亚洲", "TJ": "亚洲", "TZ": "非洲", "TH": "亚洲", "TL": "亚洲",
    "TG": "非洲", "TO": "大洋洲", "TT": "北美", "TN": "非洲", "TR": "亚洲", "TM": "亚洲", "TV": "大洋洲", "UG": "非洲",
    "UA": "欧洲", "AE": "亚洲", "GB": "欧洲", "US": "北美", "UY": "南美", "UZ": "亚洲", "VU": "大洋洲", "VA": "欧洲",
    "VE": "南美", "VN": "亚洲", "YE": "亚洲", "ZM": "非洲", "ZW": "非洲",
}


def normalize_host(host: str) -> str:
    return (host or "").strip().strip("[]").rstrip(".").lower()


def continent_from_country_code(code: str) -> str:
    return COUNTRY_CONTINENTS.get((code or "").strip().upper(), "未识别")


def is_public_ip(ip_text: str) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False, "IP 格式无效"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False, "内网或保留地址"
    return True, ""


def resolve_public_ip(host: str) -> tuple[str, str]:
    host = normalize_host(host)
    if not host:
        return "", "入口地址为空"
    try:
        parsed_ip = ipaddress.ip_address(host)
        ok, reason = is_public_ip(str(parsed_ip))
        return (str(parsed_ip), "") if ok else ("", reason)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return "", f"DNS 解析失败：{exc.__class__.__name__}"
    candidates: list[str] = []
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6) and sockaddr:
            ip_text = str(sockaddr[0])
            if ip_text not in candidates:
                candidates.append(ip_text)
    for ip_text in candidates:
        ok, _reason = is_public_ip(ip_text)
        if ok and ":" not in ip_text:
            return ip_text, ""
    for ip_text in candidates:
        ok, _reason = is_public_ip(ip_text)
        if ok:
            return ip_text, ""
    return "", "没有解析到公网 IP" if candidates else "DNS 没有返回地址"


def lookup_geo_ip_api(ip_text: str) -> dict:
    url = (
        "http://ip-api.com/json/"
        + quote(ip_text)
        + "?fields=status,message,country,countryCode,regionName,city,as,org,query"
    )
    req = Request(url, headers={"User-Agent": "VPN-Aggregator-Admin/2.4"})
    with urlopen(req, timeout=8) as resp:
        payload = json.loads(resp.read(64 * 1024).decode("utf-8", errors="replace"))
    if payload.get("status") != "success":
        raise ValueError(payload.get("message") or "GeoIP 查询失败")
    country_code = str(payload.get("countryCode") or "").upper()
    return {
        "resolved_ip": str(payload.get("query") or ip_text),
        "country": str(payload.get("country") or ""),
        "country_code": country_code,
        "continent": continent_from_country_code(country_code),
        "city": str(payload.get("city") or payload.get("regionName") or ""),
        "asn": str(payload.get("as") or ""),
        "org": str(payload.get("org") or ""),
        "source": "ip-api",
        "status": "ok",
        "error": "",
    }


def geo_cache_row(host: str) -> dict | None:
    host = normalize_host(host)
    if not host:
        return None
    with db() as conn:
        row = conn.execute("SELECT * FROM geo_cache WHERE host = ?", (host,)).fetchone()
    return dict(row) if row else None


def save_geo_cache(host: str, info: dict) -> dict:
    host = normalize_host(host)
    now = datetime.now().isoformat(timespec="seconds")
    row = {
        "host": host,
        "resolved_ip": info.get("resolved_ip", ""),
        "country": info.get("country", ""),
        "country_code": info.get("country_code", ""),
        "continent": info.get("continent", "未识别") or "未识别",
        "city": info.get("city", ""),
        "asn": info.get("asn", ""),
        "org": info.get("org", ""),
        "source": info.get("source", GEO_LOOKUP_PROVIDER or "ip-api"),
        "status": info.get("status", "unknown"),
        "error": info.get("error", ""),
        "checked_at": now,
    }
    with db() as conn:
        conn.execute(
            """
            INSERT INTO geo_cache(host, resolved_ip, country, country_code, continent, city, asn, org, source, status, error, checked_at)
            VALUES (:host, :resolved_ip, :country, :country_code, :continent, :city, :asn, :org, :source, :status, :error, :checked_at)
            ON CONFLICT(host) DO UPDATE SET
                resolved_ip = excluded.resolved_ip,
                country = excluded.country,
                country_code = excluded.country_code,
                continent = excluded.continent,
                city = excluded.city,
                asn = excluded.asn,
                org = excluded.org,
                source = excluded.source,
                status = excluded.status,
                error = excluded.error,
                checked_at = excluded.checked_at
            """,
            row,
        )
    return row


def geo_cache_fresh(row: dict) -> bool:
    try:
        checked_at = datetime.fromisoformat(row.get("checked_at", ""))
    except ValueError:
        return False
    return checked_at >= datetime.now() - timedelta(hours=max(1, GEO_CACHE_TTL_HOURS))


def get_geo_for_host(host: str, refresh: bool = False) -> dict:
    host = normalize_host(host)
    if not host or host == "未知":
        return save_geo_cache(host or "unknown", {"status": "unknown", "error": "入口地址为空", "continent": "未识别"}) if refresh else {}
    cached = geo_cache_row(host)
    if cached and not refresh and geo_cache_fresh(cached):
        return cached
    resolved_ip, resolve_error = resolve_public_ip(host)
    if resolve_error:
        return save_geo_cache(host, {"status": "private" if "保留" in resolve_error or "内网" in resolve_error else "error", "error": resolve_error, "continent": "未识别"})
    try:
        if GEO_LOOKUP_PROVIDER and GEO_LOOKUP_PROVIDER != "ip-api":
            raise ValueError(f"暂不支持 GeoIP Provider：{GEO_LOOKUP_PROVIDER}")
        return save_geo_cache(host, lookup_geo_ip_api(resolved_ip))
    except Exception as exc:
        return save_geo_cache(
            host,
            {
                "resolved_ip": resolved_ip,
                "status": "error",
                "error": str(exc)[:240],
                "continent": "未识别",
                "source": GEO_LOOKUP_PROVIDER or "ip-api",
            },
        )


def geo_cache_for_hosts(hosts: list[str]) -> dict[str, dict]:
    normalized = sorted({normalize_host(host) for host in hosts if normalize_host(host) and normalize_host(host) != "未知"})
    if not normalized:
        return {}
    placeholders = ",".join("?" for _ in normalized)
    with db() as conn:
        rows = conn.execute(f"SELECT * FROM geo_cache WHERE host IN ({placeholders})", normalized).fetchall()
    return {row["host"]: dict(row) for row in rows}


def geo_country_label(row: dict) -> str:
    if not row:
        return "未识别"
    parts = [row.get("country") or "", row.get("city") or ""]
    label = " / ".join(part for part in parts if part)
    return label or row.get("continent") or "未识别"


def monitor_status_label(monitor: dict | None) -> str:
    if not monitor:
        return ""
    load_status = str(monitor.get("load_status") or monitor.get("load_label") or "").strip().lower()
    cpu = safe_float(monitor.get("cpu_percent"))
    memory = safe_float(monitor.get("memory_percent"))
    critical_statuses = {"critical", "error", "offline", "down", "严重", "异常", "离线"}
    warning_statuses = {"warn", "warning", "degraded", "high", "中", "警告"}
    if load_status in critical_statuses or cpu >= 90 or memory >= 90:
        return "异常"
    if load_status in warning_statuses or cpu >= 80 or memory >= 80 or monitor_is_stale(monitor):
        return "警告"
    return "健康"


def node_check_status_label(status: str) -> str:
    status = (status or "").strip()
    if status in OK_NODE_CHECK_STATUSES:
        return "真可用"
    if status in FAILED_NODE_CHECK_STATUSES:
        return "真测失败"
    if status in INCONCLUSIVE_NODE_CHECK_STATUSES:
        return "跳过测试"
    if not status or status == "未测速":
        return "未真测"
    return status


def badge_tone_for_status(label: str) -> str:
    if label in {"健康", "真可用", "正常"}:
        return "ok"
    if label in {"离线", "异常", "真测失败"}:
        return "danger"
    return "warn"


def node_status_label(row: dict) -> str:
    if not row.get("enabled", 1):
        return "离线"
    test_status = str(row.get("test_status") or "").strip()
    if test_status in FAILED_NODE_CHECK_STATUSES:
        return "真测失败"
    monitor_status = monitor_status_label(row.get("monitor") or {})
    if monitor_status in {"异常", "警告"}:
        return monitor_status
    latency = row.get("last_latency_ms")
    if latency is not None and latency >= 180:
        return "警告"
    if "失败" in str(row.get("test_status") or ""):
        return "警告"
    return "健康"


def node_quality(item: dict, latency_ms, test_status: str, history: dict, geo: dict, monitor: dict, metadata: dict) -> dict:
    score = 50
    reasons = []
    success_rate = history.get("success_rate")
    if success_rate is not None:
        score = int(success_rate)
        reasons.append(f"历史成功率 {success_rate}%")
    else:
        reasons.append("缺少历史真测")
    if test_status in OK_NODE_CHECK_STATUSES:
        score += 15
        reasons.append("最近真测通过")
    elif test_status in FAILED_NODE_CHECK_STATUSES:
        score -= 35
        reasons.append("最近真测失败")
    elif test_status in INCONCLUSIVE_NODE_CHECK_STATUSES:
        score -= 8
        reasons.append("最近测试跳过")
    else:
        score -= 10
        reasons.append("未真测")
    if latency_ms is not None:
        if latency_ms <= 80:
            score += 10
        elif latency_ms <= 180:
            score += 4
        elif latency_ms <= 350:
            score -= 8
        else:
            score -= 18
        reasons.append(f"延迟 {latency_ms} ms")
    if (geo.get("status") or "") == "ok":
        score += 4
    else:
        score -= 4
        reasons.append("GeoIP 未完整识别")
    if monitor:
        if monitor_is_stale(monitor):
            score -= 6
            reasons.append("监控过期")
        else:
            score += 4
    risk_text = str(metadata.get("ip_risk") or "")
    risk_match = re.search(r"(\d+(?:\.\d+)?)%", risk_text)
    if risk_match:
        risk = float(risk_match.group(1))
        if risk >= 80:
            score -= 18
            reasons.append(f"IP 风险 {risk_text}")
        elif risk >= 50:
            score -= 10
            reasons.append(f"IP 风险 {risk_text}")
        elif risk <= 25:
            score += 3
    if not item.get("enabled", 1):
        score = min(score, 30)
        reasons.append("已停用")
    score = max(0, min(100, round(score)))
    if score >= 85:
        label, tone = "优", "ok"
    elif score >= 70:
        label, tone = "良", "ok"
    elif score >= 50:
        label, tone = "观察", "warn"
    else:
        label, tone = "风险", "danger"
    return {
        "score": score,
        "label": label,
        "tone": tone,
        "summary": "；".join(reasons[:3]) or "暂无评分依据",
    }


def node_verification_level(test_status: str, latency_ms, quality_rounds: dict) -> dict:
    if quality_rounds.get("latest_passed"):
        return {
            "grade": "L3",
            "label": "优选通过",
            "tone": "l3",
            "detail": "当前 subs-check 速度门槛通过",
        }
    if str(test_status or "").strip() in OK_NODE_CHECK_STATUSES:
        return {
            "grade": "L2",
            "label": "代理可用",
            "tone": "l2",
            "detail": "真实代理请求已通过，当前轮未进入优选池",
        }
    status = str(test_status or "").strip()
    entry_reachable = latency_ms is not None and status not in FAILED_NODE_CHECK_STATUSES and status not in INCONCLUSIVE_NODE_CHECK_STATUSES
    if entry_reachable or status in {"节点入口连通", "入口连通", "tcp_ok"}:
        return {
            "grade": "L1",
            "label": "入口可达",
            "tone": "l1",
            "detail": "仅确认入口 TCP 可达，未证明代理链路可用",
        }
    return {
        "grade": "U",
        "label": "未验证",
        "tone": "unknown",
        "detail": "没有足够的真实检测证据",
    }


def build_node_asset(item: dict, endpoint: tuple[str, int] | None, geo: dict, check: dict | None = None) -> dict:
    host = endpoint[0] if endpoint else "未知"
    check = check or {}
    monitor = item.get("monitor") or {}
    latency_ms = check.get("latency_ms", item.get("last_latency_ms"))
    test_status = check.get("status") or item.get("test_status") or "未测速"
    checked_at = check.get("checked_at") or item.get("last_tested_at") or ""
    item["display"] = display_name(item)
    item["endpoint_host"] = host
    item["endpoint_port"] = endpoint[1] if endpoint else ""
    item["resolved_ip"] = geo.get("resolved_ip") or "-"
    item["region"] = geo.get("continent") or "未识别"
    item["country_label"] = geo_country_label(geo)
    item["country_code"] = geo.get("country_code") or ""
    item["asn"] = geo.get("asn") or "-"
    item["org"] = geo.get("org") or ""
    item["geo_status"] = geo.get("status") or "unknown"
    item["geo_error"] = geo.get("error") or ""
    item["geo_source"] = geo.get("source") or ""
    item["geo_checked_at"] = geo.get("checked_at") or ""
    item["geo_checked_label"] = relative_time(geo.get("checked_at") or "") if geo.get("checked_at") else "未刷新"
    item["last_latency_ms"] = latency_ms
    item["last_tested_at"] = checked_at
    item["test_status"] = test_status
    item["check_status_label"] = node_check_status_label(test_status)
    item["check_status_tone"] = badge_tone_for_status(item["check_status_label"])
    history = item.get("check_history") or {}
    item["check_history"] = history
    item["success_rate_label"] = history.get("success_rate_label", "暂无")
    item["avg_latency_label"] = history.get("avg_latency_label", "-")
    item["last_failed_label"] = history.get("last_failed_label", "无")
    metadata = item.get("metadata") or {}
    item["metadata"] = metadata
    item["media_labels"] = metadata.get("media") or []
    item["media_label"] = "、".join(item["media_labels"]) if item["media_labels"] else "未检测"
    item["speed_label"] = metadata.get("speed_label") or "-"
    item["ip_risk_label"] = metadata.get("ip_risk") or "-"
    item["metadata_updated_label"] = metadata.get("updated_label") or "未更新"
    quality_rounds = item.get("quality_rounds") or {}
    item["quality_rounds"] = quality_rounds
    item["quality_rounds_label"] = quality_rounds.get("rounds_label") or "暂无自动轮次"
    item["quality_stability_label"] = quality_rounds.get("stability_label") or "未形成样本"
    item["quality_stability_tone"] = quality_rounds.get("stability_tone") or "neutral"
    if not item["speed_label"] and quality_rounds.get("last_speed_label"):
        item["speed_label"] = quality_rounds["last_speed_label"]
    verification = node_verification_level(test_status, latency_ms, quality_rounds)
    item["verification"] = verification
    item["quality_grade"] = verification["grade"]
    item["quality_grade_label"] = verification["label"]
    item["quality_grade_tone"] = verification["tone"]
    item["quality_grade_detail"] = verification["detail"]
    item["latency_label"] = f"{latency_ms} ms" if latency_ms is not None else "-"
    item["tested_label"] = relative_time(checked_at) if checked_at else "未测速"
    item["monitor"] = monitor
    item["monitoring_available"] = bool(monitor)
    item["monitoring_label"] = monitor.get("reported_label") if monitor else "未接入"
    item["monitor_status_label"] = monitor_status_label(monitor)
    item["monitor_fresh"] = bool(monitor) and not monitor_is_stale(monitor)
    item["status_label"] = node_status_label(item)
    item["status_tone"] = badge_tone_for_status(item["status_label"])
    quality = node_quality(item, latency_ms, test_status, history, geo, monitor, metadata)
    item["quality"] = quality
    item["quality_score"] = quality["score"]
    item["quality_label"] = quality["label"]
    item["quality_tone"] = quality["tone"]
    item["quality_summary"] = quality["summary"]
    item["is_filtered_upstream"] = item.get("source_type") == "upstream" and FILTER_FAILED_UPSTREAM_NODES and not upstream_check_allows_subscription(test_status)
    if item.get("source_type") == "upstream":
        if not FILTER_FAILED_UPSTREAM_NODES:
            item["subscription_state_label"] = "订阅下发"
        elif upstream_check_allows_subscription(test_status):
            item["subscription_state_label"] = "订阅下发"
        elif test_status in FAILED_NODE_CHECK_STATUSES:
            item["subscription_state_label"] = "已从订阅过滤"
        else:
            item["subscription_state_label"] = "未真测不下发"
    elif item.get("enabled", 1):
        item["subscription_state_label"] = "订阅下发"
    else:
        item["subscription_state_label"] = "已停用"
    return item


def node_view_rows(limit: int | None = None, include_upstream: bool = True) -> list[dict]:
    rows: list[dict] = []
    manual_rows = [dict(row) for row in list_node_rows()]
    upstream_rows = load_upstream_node_items(enabled_only=False) if include_upstream else []
    checks = list_node_checks()
    histories = list_node_check_history_stats()
    monitors = list_latest_node_monitors()
    metadata_map = list_node_metadata()
    quality_rounds_map, _quality_runs = list_node_quality_rounds(3)
    assets: list[dict] = []
    for row in manual_rows:
        row["asset_key"] = f"manual:{row['id']}"
        row["source_type"] = "manual"
        row["source_label"] = "手动"
        row["upstream_name"] = ""
        row["readonly"] = False
        assets.append(row)
    for row in upstream_rows:
        row["asset_key"] = upstream_asset_key(row)
        row["source_type"] = "upstream"
        row["source_label"] = "上游订阅"
        row["display_name"] = row.get("name", "")
        row["enabled"] = int(row.get("upstream_enabled") or 0)
        row["last_latency_ms"] = None
        row["last_tested_at"] = ""
        row["test_status"] = checks.get(row["asset_key"], {}).get("status", "未测速")
        row["readonly"] = True
        assets.append(row)
    for row in assets:
        row["monitor"] = monitors.get(row["asset_key"], {})
        row["check_history"] = histories.get(row["asset_key"], {})
        row["metadata"] = metadata_map.get(row["asset_key"], {})
        row["quality_rounds"] = quality_rounds_map.get(row["asset_key"], {})
    endpoints = [(row["asset_key"], node_endpoint(row["raw"])) for row in assets]
    cache = geo_cache_for_hosts([endpoint[0] for _asset_key, endpoint in endpoints if endpoint])
    endpoint_map = {asset_key: endpoint for asset_key, endpoint in endpoints}
    for item in assets:
        endpoint = endpoint_map.get(item["asset_key"])
        host = endpoint[0] if endpoint else "未知"
        geo = cache.get(normalize_host(host), {})
        rows.append(build_node_asset(item, endpoint, geo, checks.get(item["asset_key"])))
    if limit:
        return rows[:limit]
    return rows


def filter_nodes(rows: list[dict], filters: dict) -> list[dict]:
    query = (filters.get("q") or "").strip().lower()
    region = (filters.get("region") or "").strip()
    status = (filters.get("status") or "").strip()
    protocol = (filters.get("protocol") or "").strip().lower()
    result = rows
    if query:
        def matches(row: dict) -> bool:
            haystack = " ".join(
                str(row.get(key, ""))
                for key in (
                    "display", "name", "endpoint_host", "endpoint_port", "resolved_ip", "protocol",
                    "region", "country_label", "country_code", "asn", "org", "geo_status", "status_label",
                    "check_status_label", "subscription_state_label", "source_label", "upstream_name", "asset_key", "raw",
                )
            ).lower()
            return query in haystack

        result = [row for row in result if matches(row)]
    if region:
        result = [row for row in result if row.get("region") == region or row.get("country_label") == region or row.get("country_code") == region]
    if status:
        result = [
            row for row in result
            if row.get("status_label") == status or row.get("check_status_label") == status or row.get("subscription_state_label") == status
        ]
    if protocol:
        result = [row for row in result if str(row.get("protocol") or "").lower() == protocol]
    return result


def record_traffic_snapshot(upload_bytes: int, download_bytes: int, connections: int, anomalies: int, blocked_ips: int) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO traffic_snapshots(upload_bytes, download_bytes, connections, anomalies, blocked_ips, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (max(0, upload_bytes), max(0, download_bytes), max(0, connections), max(0, anomalies), max(0, blocked_ips), now),
        )


def record_traffic_event(item: dict, traffic_key: str, user_name: str = "") -> dict:
    upload = safe_int(item.get("upload") or item.get("upload_bytes"))
    download = safe_int(item.get("download") or item.get("download_bytes"))
    if not upload and not download and item.get("delta_bytes") is not None:
        download = safe_int(item.get("delta_bytes"))
    risk = str(item.get("risk") or "低").strip() or "低"
    action = str(item.get("action") or ("封禁IP" if item.get("blocked_ip") else "记录")).strip() or "记录"
    blocked_ip = str(item.get("blocked_ip") or "").strip()
    source_ip = str(item.get("source_ip") or item.get("ip") or blocked_ip or "").strip()
    protocol = str(item.get("protocol") or "").strip()
    node = str(item.get("node") or item.get("node_name") or "").strip()
    message = str(item.get("message") or item.get("reason") or "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO traffic_events(
                traffic_key, user_name, source_ip, node, protocol, upload_bytes, download_bytes, risk, action, message, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (traffic_key, user_name, source_ip, node, protocol, upload, download, risk, action, message, now),
        )
    return {
        "upload": upload,
        "download": download,
        "connections": safe_int(item.get("connections"), 1),
        "anomaly": 1 if risk in {"中", "高", "严重", "medium", "high", "critical"} or action in {"封禁IP", "block", "reject"} else 0,
        "blocked": 1 if blocked_ip or action in {"封禁IP", "block"} else 0,
    }


def record_subscription_access_event(user: sqlite3.Row | dict | None, fmt: str, response: Response, force_engine: str = "") -> Response:
    if not user or response.status_code >= 400:
        return response
    try:
        size = response.calculate_content_length()
        if size is None:
            size = len(response.get_data())
    except Exception:
        size = 0
    traffic_key = str(user["traffic_key"] or "").strip()
    user_name = str(user["name"] or "").strip()
    source_ip = (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        or request.remote_addr
        or ""
    )
    engine = response.headers.get("X-Subscription-Engine", "")
    decision = response.headers.get("X-Subscription-Decision", "")
    record_traffic_event(
        {
            "download": max(0, int(size or 0)),
            "connections": 1,
            "source_ip": source_ip,
            "node": "订阅下发",
            "protocol": f"subscription/{fmt}",
            "risk": "低",
            "action": "订阅访问",
            "message": f"{engine or 'local'} · {decision or force_engine or 'default'}；仅记录订阅文件下发，不计入代理用量",
        },
        traffic_key,
        user_name,
    )
    return response


def traffic_range_start(range_key: str) -> datetime:
    now = datetime.now()
    if range_key == "1h":
        return now - timedelta(hours=1)
    if range_key == "7d":
        return now - timedelta(days=7)
    if range_key == "30d":
        return now - timedelta(days=30)
    return now - timedelta(hours=24)


def normalized_traffic_range(value: str) -> str:
    return value if value in {"1h", "24h", "7d", "30d"} else "24h"


def list_traffic_snapshots(limit: int = 48) -> list[dict]:
    with db() as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM traffic_snapshots ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            )
        ]
    return list(reversed(rows))


def list_all_audit_logs(limit: int = 1000) -> list[dict]:
    with db() as conn:
        return [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 5000)),),
            )
        ]


def traffic_event_filters_sql(risk: str = "", protocol: str = "", q: str = "", range_key: str = "") -> tuple[str, list[str | int]]:
    clauses = []
    params: list[str | int] = []
    if risk:
        clauses.append("risk = ?")
        params.append(risk)
    if protocol:
        clauses.append("protocol = ?")
        params.append(protocol)
    if q:
        like = f"%{q.strip()}%"
        clauses.append(
            "(traffic_key LIKE ? OR user_name LIKE ? OR source_ip LIKE ? OR node LIKE ? OR protocol LIKE ? OR risk LIKE ? OR action LIKE ? OR message LIKE ?)"
        )
        params.extend([like] * 8)
    if range_key:
        start = traffic_range_start(normalized_traffic_range(range_key)).isoformat(timespec="seconds")
        clauses.append("created_at >= ?")
        params.append(start)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def count_traffic_events(risk: str = "", protocol: str = "", q: str = "", range_key: str = "") -> int:
    where, params = traffic_event_filters_sql(risk=risk, protocol=protocol, q=q, range_key=range_key)
    with db() as conn:
        row = conn.execute(f"SELECT COUNT(*) AS total FROM traffic_events {where}", params).fetchone()
    return int(row["total"] if row else 0)


def count_proxy_traffic_events() -> int:
    with db() as conn:
        row = conn.execute("SELECT COUNT(*) AS total FROM traffic_events WHERE action <> '订阅访问'").fetchone()
    return int(row["total"] if row else 0)


def query_traffic_events(
    limit: int = 80,
    offset: int = 0,
    risk: str = "",
    protocol: str = "",
    q: str = "",
    range_key: str = "",
) -> list[dict]:
    where, params = traffic_event_filters_sql(risk=risk, protocol=protocol, q=q, range_key=range_key)
    params.extend([max(1, limit), max(0, offset)])
    with db() as conn:
        return [
            dict(row)
            for row in conn.execute(
                f"SELECT * FROM traffic_events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                params,
            )
        ]


def list_traffic_events(limit: int = 80, risk: str = "", protocol: str = "", q: str = "", range_key: str = "") -> list[dict]:
    return query_traffic_events(limit=max(1, limit), risk=risk, protocol=protocol, q=q, range_key=range_key)


def traffic_ingestion_status() -> dict:
    with db() as conn:
        last_event = conn.execute("SELECT created_at FROM traffic_events ORDER BY id DESC LIMIT 1").fetchone()
        matched = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM traffic_events
            WHERE traffic_key <> ''
              AND traffic_key IN (SELECT traffic_key FROM subscribers WHERE traffic_key <> '')
            """
        ).fetchone()["total"]
        unmatched = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM traffic_events
            WHERE traffic_key <> ''
              AND traffic_key NOT IN (SELECT traffic_key FROM subscribers WHERE traffic_key <> '')
            """
        ).fetchone()["total"]
        queue = [
            dict(row)
            for row in conn.execute(
                """
                SELECT *
                FROM traffic_events
                WHERE traffic_key <> ''
                  AND traffic_key NOT IN (SELECT traffic_key FROM subscribers WHERE traffic_key <> '')
                ORDER BY id DESC
                LIMIT 8
                """
            )
        ]
    return {
        "last_report_label": relative_time(last_event["created_at"]) if last_event else "从未",
        "matched": int(matched or 0),
        "unmatched": int(unmatched or 0),
        "queue": queue,
    }


def node_monitoring_status() -> dict:
    latest = latest_node_monitor_report()
    with db() as conn:
        asset_count = conn.execute("SELECT COUNT(DISTINCT asset_key) AS total FROM node_monitor_snapshots").fetchone()["total"]
    return {
        "enabled": bool(latest),
        "asset_count": int(asset_count or 0),
        "last_report": latest,
        "last_report_label": latest["reported_label"] if latest else "从未",
    }


def bucket_traffic_snapshots(range_key: str) -> dict:
    range_key = normalized_traffic_range(range_key)
    now = datetime.now()
    if range_key == "1h":
        bucket_seconds = 5 * 60
        bucket_count = 12
        label_fmt = "%H:%M"
    elif range_key == "7d":
        bucket_seconds = 24 * 60 * 60
        bucket_count = 7
        label_fmt = "%m-%d"
    elif range_key == "30d":
        bucket_seconds = 24 * 60 * 60
        bucket_count = 30
        label_fmt = "%m-%d"
    else:
        bucket_seconds = 60 * 60
        bucket_count = 24
        label_fmt = "%H:%M"
    start = now - timedelta(seconds=bucket_seconds * bucket_count)
    buckets = [
        {
            "start": start + timedelta(seconds=bucket_seconds * index),
            "upload": 0,
            "download": 0,
            "connections": 0,
        }
        for index in range(bucket_count)
    ]
    with db() as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT upload_bytes, download_bytes, connections, created_at
                FROM traffic_snapshots
                WHERE created_at >= ?
                ORDER BY created_at ASC
                """,
                (start.isoformat(timespec="seconds"),),
            )
        ]
    for row in rows:
        try:
            created_at = datetime.fromisoformat(row["created_at"])
        except (TypeError, ValueError):
            continue
        index = int((created_at - start).total_seconds() // bucket_seconds)
        if 0 <= index < bucket_count:
            buckets[index]["upload"] += int(row["upload_bytes"] or 0)
            buckets[index]["download"] += int(row["download_bytes"] or 0)
            buckets[index]["connections"] += int(row["connections"] or 0)
    labels = [bucket["start"].strftime(label_fmt) for bucket in buckets]
    upload = [bucket["upload"] for bucket in buckets]
    download = [bucket["download"] for bucket in buckets]
    total = [bucket["upload"] + bucket["download"] for bucket in buckets]
    max_value = max(total + upload + download + [0])
    return {
        "labels": labels,
        "upload": upload,
        "download": download,
        "total": total,
        "max_value": max_value,
        "has_data": any(value > 0 for value in total),
        "range": range_key,
    }


def traffic_summary() -> dict:
    today = datetime.now().strftime("%Y-%m-%d")
    with db() as conn:
        snap = conn.execute(
            """
            SELECT
                COALESCE(SUM(upload_bytes), 0) AS upload_bytes,
                COALESCE(SUM(download_bytes), 0) AS download_bytes,
                COALESCE(SUM(connections), 0) AS connections,
                COALESCE(SUM(anomalies), 0) AS anomalies,
                COALESCE(SUM(blocked_ips), 0) AS blocked_ips
            FROM traffic_snapshots
            WHERE created_at >= ?
            """,
            (today,),
        ).fetchone()
        total_events = conn.execute("SELECT COUNT(*) AS total FROM traffic_events").fetchone()["total"]
    upload = int(snap["upload_bytes"] or 0)
    download = int(snap["download_bytes"] or 0)
    total = upload + download
    return {
        "upload_bytes": upload,
        "download_bytes": download,
        "total_bytes": total,
        "traffic_label": format_bytes(total),
        "upload_label": format_bytes(upload),
        "download_label": format_bytes(download),
        "connections": int(snap["connections"] or 0),
        "connections_label": compact_number(snap["connections"] or 0),
        "anomalies": int(snap["anomalies"] or 0),
        "blocked_ips": int(snap["blocked_ips"] or 0),
        "event_count": int(total_events or 0),
        "bandwidth_label": f"{max(1, round(total / 1024 / 1024 / 128, 2))} Mbps" if total else "0 Mbps",
    }


def traffic_chart(range_key: str = "24h") -> dict:
    bucketed = bucket_traffic_snapshots(range_key)
    upload = bucketed["upload"]
    download = bucketed["download"]
    total = bucketed["total"]
    max_value = bucketed["max_value"]
    return {
        "labels": bucketed["labels"],
        "upload_points": line_points_scaled(upload, max_value),
        "download_points": line_points_scaled(download, max_value),
        "total_points": line_points_scaled(total, max_value),
        "spark_total": line_points_scaled(total, max_value, 180, 46),
        "max_label": format_bytes(max_value),
        "has_data": bucketed["has_data"],
        "range": bucketed["range"],
    }


def protocol_distribution() -> list[dict]:
    with db() as conn:
        rows = [
            (row["protocol"] or "未知", int(row["bytes"] or 0))
            for row in conn.execute(
                """
                SELECT protocol, SUM(upload_bytes + download_bytes) AS bytes
                FROM traffic_events
                WHERE protocol <> '' AND action <> '订阅访问'
                GROUP BY protocol
                ORDER BY bytes DESC
                LIMIT 6
                """
            )
        ]
    total = sum(value for _label, value in rows)
    if total <= 0:
        return []
    result = []
    cursor = 0
    for index, (label, value) in enumerate(rows):
        item_percent = percent(value, total)
        end = 100 if index == len(rows) - 1 else min(100, cursor + item_percent)
        color = f"hsl({index * 48 + 174}, 72%, 45%)"
        result.append(
            {
                "label": label,
                "value": value,
                "label_value": format_bytes(value) if value > 1024 else value,
                "percent": item_percent,
                "start": cursor,
                "end": end,
                "color": color,
            }
        )
        cursor = end
    return result


def geo_distribution(rows: list[dict]) -> dict:
    recognized = [row for row in rows if row.get("geo_status") == "ok"]
    pending = [row for row in rows if row.get("geo_status") in {"unknown", ""}]
    errors = [row for row in rows if row.get("geo_status") in {"error", "private"}]
    region_counts: dict[str, int] = {}
    country_counts: dict[str, int] = {}
    asn_counts: dict[str, int] = {}
    for row in recognized:
        region = row.get("region") or "未识别"
        country = row.get("country_label") or "未识别"
        asn = row.get("asn") or row.get("org") or "未知 ASN"
        region_counts[region] = region_counts.get(region, 0) + 1
        country_counts[country] = country_counts.get(country, 0) + 1
        asn_counts[asn] = asn_counts.get(asn, 0) + 1
    region_order = ["亚洲", "北美", "欧洲", "南美", "大洋洲", "非洲", "未识别"]
    region_items = [(label, region_counts.get(label, 0)) for label in region_order if region_counts.get(label, 0) or label == "未识别"]
    return {
        "recognized": len(recognized),
        "pending": len(pending),
        "errors": len(errors),
        "total": len(rows),
        "region_items": chart_items(region_items, max(1, len(rows))),
        "country_items": chart_items(sorted(country_counts.items(), key=lambda item: item[1], reverse=True)[:6], max(1, len(recognized))),
        "asn_items": chart_items(sorted(asn_counts.items(), key=lambda item: item[1], reverse=True)[:5], max(1, len(recognized))),
    }


def onboarding_tasks(nodes: list[dict], users: list[dict], upstreams: list[dict], traffic: dict, geo: dict) -> list[dict]:
    untested = len([row for row in nodes if not row.get("last_tested_at")])
    tasks = [
        {
            "title": "完善节点地理识别",
            "status": f"{geo['recognized']} / {geo['total']} 已识别",
            "tone": "ok" if geo["total"] and geo["recognized"] == geo["total"] else "warn",
            "href": url_for("nodes_admin"),
            "action": "去刷新",
        },
        {
            "title": "检测节点连通性",
            "status": f"{untested} 个未测速" if untested else "全部已有测速记录",
            "tone": "ok" if not untested else "warn",
            "href": url_for("nodes_admin"),
            "action": "去检测",
        },
        {
            "title": "添加上游订阅源",
            "status": f"{len(upstreams)} 个上游源",
            "tone": "ok" if upstreams else "warn",
            "href": url_for("nodes_admin") + "#upstreams",
            "action": "添加上游",
        },
        {
            "title": "创建首个用户",
            "status": f"{len(users)} 个用户",
            "tone": "ok" if users else "warn",
            "href": url_for("users_admin") + "#new-user",
            "action": "创建用户",
        },
        {
            "title": "接入流量上报",
            "status": f"{traffic['event_count']} 条事件",
            "tone": "ok" if traffic["event_count"] else "warn",
            "href": url_for("traffic_admin"),
            "action": "查看说明",
        },
    ]
    return tasks


def system_checks() -> dict:
    nodes = node_view_rows()
    users = list_subscribers()
    upstreams = list_upstreams()
    traffic = traffic_summary()
    geo = geo_distribution(nodes)
    backups = backup_status()
    default_password = is_default_password()
    monitoring = node_monitoring_status()
    subs_check = subs_check_status()
    public_sub = public_subscription_status()
    checks = [
        {"label": "节点资产", "ok": bool(nodes), "detail": f"{len(nodes)} 个节点"},
        {"label": "GeoIP 识别", "ok": geo["total"] > 0 and geo["recognized"] == geo["total"], "detail": f"{geo['recognized']} / {geo['total']} 已识别"},
        {"label": "上游订阅", "ok": any(row.get("verify_status") == "正常" for row in upstreams), "detail": f"{len(upstreams)} 个上游源"},
        {"label": "subs-check", "ok": subs_check["ok"], "detail": subs_check["message"]},
        {"label": "用户订阅", "ok": bool(users), "detail": f"{len(users)} 个用户"},
        {"label": "流量上报", "ok": traffic["event_count"] > 0, "detail": f"{traffic['event_count']} 条事件"},
        {"label": "节点监控", "ok": monitoring["enabled"], "detail": f"{monitoring['asset_count']} 个资产 · 最近 {monitoring['last_report_label']}"},
        {"label": "公开订阅入口", "ok": not public_sub["enabled"], "detail": public_sub["detail"]},
        {"label": "订阅 Token", "ok": bool(SUB_TOKEN), "detail": "已启用" if SUB_TOKEN else "未启用"},
        {"label": "默认密码", "ok": not default_password, "detail": "已修改" if not default_password else "仍为 admin/admin"},
        {"label": "备份目录", "ok": backups["writable"], "detail": backups["dir"]},
        {"label": "备份演练", "ok": backups["drill"]["ok"], "detail": f"{backups['drill']['label']} · {backups['drill']['checked_label']}"},
        {"label": "公网地址", "ok": bool(PUBLIC_BASE_URL), "detail": PUBLIC_BASE_URL or "未设置 PUBLIC_BASE_URL"},
    ]
    ordered_checks = sorted(checks, key=lambda item: (item["ok"], item["label"]))
    return {
        "checks": ordered_checks,
        "passed": len([item for item in checks if item["ok"]]),
        "total": len(checks),
        "default_password": default_password,
        "backup": backups,
        "data_dir": str(DATA_DIR),
        "db_file": str(DB_FILE),
        "nodes_file": str(NODES_FILE),
        "public_base_url": PUBLIC_BASE_URL or "",
        "subscription_token_enabled": bool(SUB_TOKEN),
        "public_subscription": public_sub,
        "traffic": traffic_ingestion_status(),
        "monitoring": monitoring,
        "subs_check": subs_check,
    }


def search_context(q: str) -> dict:
    q = (q or "").strip().lower()
    all_nodes = node_view_rows()
    users = list_subscribers()
    events = list_traffic_events(20, q=q)
    logs = list_audit_logs(20)
    if q:
        node_hits = [
            row for row in all_nodes
            if q in " ".join(
                str(row.get(key, ""))
                for key in ("display", "asset_key", "endpoint_host", "resolved_ip", "country_label", "region", "asn", "org", "protocol", "source_label", "upstream_name")
            ).lower()
        ]
        user_hits = [
            user for user in users
            if q in " ".join(str(user.get(key, "")) for key in ("name", "note", "traffic_key", "status", "expire_at")).lower()
        ]
        log_hits = [log for log in logs if q in " ".join(str(log.get(key, "")) for key in ("action", "target_type", "target_id", "message", "actor", "ip")).lower()]
    else:
        node_hits = []
        user_hits = []
        log_hits = []
    upstream_hits = [
        row for row in list_upstreams()
        if q in " ".join(str(row.get(key, "")) for key in ("name", "url", "last_status", "source_label", "filter_label")).lower()
    ] if q else []
    return {
        "q": q,
        "nodes": node_hits[:8],
        "users": user_hits[:8],
        "events": events[:8],
        "logs": log_hits[:8],
        "upstreams": upstream_hits[:8],
        "total": len(node_hits) + len(user_hits) + len(events) + len(log_hits) + len(upstream_hits),
    }


def report_payload() -> dict:
    nodes = node_view_rows()
    users = list_subscribers()
    upstreams = list_upstreams()
    traffic = traffic_summary()
    geo = geo_distribution(nodes)
    checks = system_checks()
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "app_version": APP_VERSION,
        "public_base_url": public_base_url(),
        "checks": checks["checks"],
        "summary": {
            "nodes": {
                "total": len(nodes),
                "manual": len([row for row in nodes if row.get("source_type") == "manual"]),
                "upstream": len([row for row in nodes if row.get("source_type") == "upstream"]),
                "healthy": len([row for row in nodes if row.get("status_label") == "健康"]),
                "monitored": len([row for row in nodes if row.get("monitoring_available")]),
            },
            "geo": geo,
            "users": subscriber_summary(users),
            "traffic": traffic,
            "upstreams": {
                "total": len(upstreams),
                "enabled": len([row for row in upstreams if row.get("enabled")]),
                "errors": len([row for row in upstreams if row.get("last_status") == "同步失败"]),
            },
        },
        "recent_risk_events": list_traffic_events(20, risk="高") + list_traffic_events(20, risk="严重"),
    }


def overview_context() -> dict:
    rows = list_node_rows()
    users = list_subscribers()
    upstreams = list_upstreams()
    summary = traffic_summary()
    range_key = normalized_traffic_range(request.args.get("range", "24h"))
    all_node_rows = node_view_rows()
    node_rows = sorted(
        all_node_rows,
        key=lambda row: (
            0 if row.get("status_label") != "健康" else 1,
            0 if row.get("check_status_label") == "真测失败" else 1,
            -(safe_int(row.get("last_latency_ms")) if row.get("last_latency_ms") is not None else -1),
        ),
    )[:6]
    geo = geo_distribution(all_node_rows)
    checks = system_checks()
    alerts = list_traffic_events(6, risk="高") + list_traffic_events(6, risk="严重")
    engine = subscription_engine_state()
    check_failures = [item for item in checks["checks"] if not item["ok"]]
    manual_assets = len([row for row in all_node_rows if row.get("source_type") == "manual"])
    upstream_assets = len([row for row in all_node_rows if row.get("source_type") == "upstream"])
    healthy_assets = len([row for row in all_node_rows if row.get("status_label") == "健康"])
    warning_assets = len([row for row in all_node_rows if row.get("status_label") == "警告"])
    failed_assets = len([row for row in all_node_rows if row.get("status_label") in {"离线", "异常", "真测失败"}])
    proxy_ok_assets = len([row for row in all_node_rows if row.get("check_status_label") == "真可用"])
    filtered_assets = len([row for row in all_node_rows if row.get("is_filtered_upstream")])
    monitored_assets = len([row for row in all_node_rows if row.get("monitoring_available")])
    mode_labels = {"local": "全量节点池", "balanced": "自动优选", "strict": "严格优选"}
    asset_summary = {
        "total": len(all_node_rows),
        "manual": manual_assets,
        "upstream": upstream_assets,
        "healthy": healthy_assets,
        "warning": warning_assets,
        "failed": failed_assets,
        "proxy_ok": proxy_ok_assets,
        "filtered": filtered_assets,
        "monitored": monitored_assets,
        "health_percent": percent(healthy_assets, len(all_node_rows)),
        "geo_percent": percent(geo["recognized"], geo["total"]),
        "proxy_percent": percent(proxy_ok_assets, len(all_node_rows)),
        "l3": len([row for row in all_node_rows if row.get("quality_grade") == "L3"]),
        "l2": len([row for row in all_node_rows if row.get("quality_grade") == "L2"]),
        "l1": len([row for row in all_node_rows if row.get("quality_grade") == "L1"]),
        "unverified": len([row for row in all_node_rows if row.get("quality_grade") == "U"]),
    }
    return {
        "page_title": "运营总览",
        "users": users,
        "user_summary": subscriber_summary(users),
        "traffic": summary,
        "chart": traffic_chart(range_key),
        "range": range_key,
        "protocols": protocol_distribution(),
        "node_rows": node_rows,
        "alerts": alerts[:6],
        "active_nodes": asset_summary["healthy"],
        "total_nodes": asset_summary["total"],
        "asset_summary": asset_summary,
        "upstreams": upstreams,
        "geo": geo,
        "checks": checks,
        "check_failures": check_failures[:5],
        "check_failure_count": len(check_failures),
        "onboarding_tasks": onboarding_tasks(all_node_rows, users, upstreams, summary, geo),
        "region_items": geo["region_items"],
        "engine": engine,
        "engine_mode_label": mode_labels.get(engine["mode"], engine["mode"]),
        "links": [
            ("自动", DINGYUE_PATH),
            ("Clash", f"{DINGYUE_PATH}/clash"),
            ("优选", f"{DINGYUE_PATH}/best"),
            ("V2Ray", f"{DINGYUE_PATH}/v2ray"),
            ("Surge", f"{DINGYUE_PATH}/surge"),
            ("QX", f"{DINGYUE_PATH}/qx"),
        ],
        "base": public_base_url(),
    }


def nodes_context() -> dict:
    all_rows = node_view_rows()
    filters = {
        "q": request.args.get("q", "").strip(),
        "region": request.args.get("region", "").strip(),
        "status": request.args.get("status", "").strip(),
        "protocol": request.args.get("protocol", "").strip(),
    }
    rows = filter_nodes(all_rows, filters)
    upstreams = list_upstreams()
    page, per_page = pagination_args(20, 100)
    pager = paginate_items(rows, page, per_page)
    rows_page = pager["items"]
    selected_key = request.args.get("asset_key", "").strip()
    selected_id = safe_int(request.args.get("node_id"))
    selected = next((row for row in rows if row["asset_key"] == selected_key), None)
    if not selected and selected_id:
        selected = next((row for row in rows if row.get("source_type") == "manual" and row["id"] == selected_id), None)
    selected = selected or (rows_page[0] if rows_page else None) or (rows[0] if rows else None)
    protocol_options = sorted({row.get("protocol") or "unknown" for row in all_rows})
    region_options = [item["label"] for item in geo_distribution(all_rows)["region_items"] if item["label"] != "未识别"]
    if any(row.get("region") == "未识别" for row in all_rows):
        region_options.append("未识别")
    geo_ok_count = len([row for row in all_rows if row.get("geo_status") == "ok"])
    geo_pending_count = len([row for row in all_rows if row.get("geo_status") in {"unknown", ""}])
    untested_count = len([row for row in all_rows if not row.get("last_tested_at")])
    upstream_all_count = len([row for row in all_rows if row.get("source_type") == "upstream"])
    upstream_filtered_count = len([row for row in all_rows if row.get("is_filtered_upstream")])
    upstream_proxy_ok_count = len([row for row in all_rows if row.get("source_type") == "upstream" and row.get("check_status_label") == "真可用"])
    engine = subscription_engine_state()
    subscription_node_count = engine["default_output_count"]
    subs_status = engine["subs_check"]
    subs_api = subs_check_api_status(timeout=2)
    status_options = []
    for item in ["健康", "警告", "离线", "异常", "真可用", "真测失败", "未真测", "订阅下发", "已从订阅过滤", "未真测不下发"]:
        if any(row.get("status_label") == item or row.get("check_status_label") == item or row.get("subscription_state_label") == item for row in all_rows):
            status_options.append(item)
    return {
        "page_title": "节点管理",
        "all_rows": all_rows,
        "rows": rows_page,
        "pager": pager,
        "nodes_text": "\n".join(reversed([row["raw"] for row in all_rows if row["enabled"] and row.get("source_type") == "manual"])),
        "filters": filters,
        "protocol_options": protocol_options,
        "region_options": region_options,
        "upstreams": upstreams,
        "upstream_count": len(upstreams),
        "upstream_enabled_count": len([item for item in upstreams if item["enabled"]]),
        "upstream_node_count": upstream_all_count,
        "upstream_subscription_count": upstream_all_count - upstream_filtered_count,
        "upstream_proxy_ok_count": upstream_proxy_ok_count,
        "upstream_filtered_count": upstream_filtered_count,
        "subscription_node_count": subscription_node_count,
        "engine": engine,
        "subs_check_status": subs_status,
        "subs_check_api": subs_api,
        "subs_check_config": subs_check_config_summary(),
        "subs_check_runs": list_subs_check_runs(),
        "quality_summary": engine["quality"],
        "subs_check_logs": subs_check_api_logs(8, timeout=2),
        "upstream_error_count": len([item for item in upstreams if item.get("last_status") == "同步失败"]),
        "status_options": status_options,
        "selected_node": selected,
        "health_count": len([row for row in all_rows if row["status_label"] == "健康"]),
        "warning_count": len([row for row in all_rows if row["status_label"] == "警告"]),
        "offline_count": len([row for row in all_rows if row["status_label"] == "离线"]),
        "geo_ok_count": geo_ok_count,
        "geo_pending_count": geo_pending_count,
        "untested_count": untested_count,
        "return_test_host": return_test_host(),
        "return_test_port": return_test_port(),
        "return_test_target": return_test_target_label(),
    }


def users_context() -> dict:
    all_users = list_subscribers()
    filters = {"q": request.args.get("q", "").strip(), "status": request.args.get("status", "").strip()}
    users = filter_subscribers(all_users, filters["q"], filters["status"])
    page, per_page = pagination_args(20, 100)
    pager = paginate_items(users, page, per_page)
    return {
        "page_title": "用户与套餐",
        "users": pager["items"],
        "pager": pager,
        "plans": list_plans(),
        "summary": subscriber_summary(all_users),
        "charts": user_charts(all_users),
        "warnings": [user for user in all_users if user["is_warning"]],
        "filters": filters,
        "base": public_base_url(),
    }


def traffic_context() -> dict:
    range_key = normalized_traffic_range(request.args.get("range", "").strip())
    risk = request.args.get("risk", "").strip()
    protocol = request.args.get("protocol", "").strip()
    q = request.args.get("q", "").strip()
    page, per_page = pagination_args(50, 200)
    total = count_traffic_events(risk=risk, protocol=protocol, q=q, range_key=range_key)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    events = query_traffic_events(per_page, (page - 1) * per_page, risk=risk, protocol=protocol, q=q, range_key=range_key)
    pager = paginate_db_items(events, total, page, per_page)
    return {
        "page_title": "流量监控与审计",
        "traffic": traffic_summary(),
        "ingestion": traffic_ingestion_status(),
        "proxy_event_count": count_proxy_traffic_events(),
        "chart": traffic_chart(range_key),
        "protocols": protocol_distribution(),
        "events": events,
        "pager": pager,
        "filters": {"range": range_key, "risk": risk, "protocol": protocol, "q": q},
        "audit_logs": list_audit_logs(20),
        "base": public_base_url(),
    }


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_app_globals():
    return {
        "app_version": APP_VERSION,
        "admin_username": current_admin_user(),
        "sidebar_status": sidebar_system_status(),
    }


def sidebar_system_status() -> dict:
    database_ok = False
    try:
        with db() as conn:
            database_ok = conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    except Exception:
        database_ok = False
    try:
        engine = subscription_engine_state(status_timeout=1)
        output_count = safe_int(engine.get("default_output_count"))
        output_label = engine.get("default_output_label") or f"{output_count} 个节点"
    except Exception:
        output_count = 0
        output_label = "无可用节点"
    return {
        "control": {"label": "运行中", "ok": True},
        "database": {"label": "正常" if database_ok else "异常", "ok": database_ok},
        "subscription": {"label": output_label if output_count else "无可用节点", "ok": output_count > 0},
    }


def public_base_url() -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    forwarded_host = request.headers.get("X-Forwarded-Host", "").split(",", 1)[0].strip()
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip() or "https"
    if forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}".rstrip("/")
    return request.host_url.rstrip("/")


def subscription_path(path: str) -> str:
    if not SUB_TOKEN:
        return path
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}token={quote(SUB_TOKEN, safe='')}"


def return_test_target_label() -> str:
    target = return_test_target()
    if target:
        return f"{target[0]}:{target[1]}"
    return "未设置，当前回退测节点入口"


def subscription_allowed() -> bool:
    if public_subscription_enabled():
        return True
    if not SUB_TOKEN:
        return False
    token = request.args.get("token", "") or request.headers.get("X-Sub-Token", "")
    return secrets.compare_digest(token, SUB_TOKEN)


def subscription_forbidden():
    return jsonify({"error": "forbidden", "hint": "public subscription is disabled; use a member /sub/<token>/... link"}), 403



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if valid_admin_login(username, password):
            session["admin"] = True
            return redirect(request.args.get("next") or url_for("admin"))
        flash("账号或密码不对")
    return render_template(
        "admin/login.html",
        username=current_admin_user(),
        default_password=is_default_password(),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def admin():
    return render_template("admin/overview.html", **overview_context())


@app.route("/admin/nodes", methods=["GET"])
@login_required
def nodes_admin():
    return render_template("admin/nodes.html", **nodes_context())


@app.route("/admin/nodes/status.json")
@login_required
def nodes_status_json():
    engine = subscription_engine_state(status_timeout=2)
    status = engine["subs_check"]
    api = subs_check_api_status(timeout=2)
    filters = {
        "q": request.args.get("q", "").strip(),
        "region": request.args.get("region", "").strip(),
        "status": request.args.get("status", "").strip(),
        "protocol": request.args.get("protocol", "").strip(),
    }
    all_rows = node_view_rows()
    filtered_rows = filter_nodes(all_rows, filters)
    upstream_all_count = len([row for row in all_rows if row.get("source_type") == "upstream"])
    upstream_filtered_count = len([row for row in all_rows if row.get("is_filtered_upstream")])
    upstream_proxy_ok_count = len([
        row for row in all_rows
        if row.get("source_type") == "upstream" and row.get("check_status_label") == "真可用"
    ])
    proxy_count = max(0, safe_int(api.get("proxy_count")))
    progress = max(0, safe_int(api.get("progress")))
    available = max(0, safe_int(api.get("available")))
    speed_done = max(0, safe_int(api.get("speed_done")))
    speed_pass = max(0, safe_int(api.get("speed_pass")))
    alive_percent = 0 if proxy_count <= 0 else min(100, round(progress / proxy_count * 100))
    available_percent = 0 if proxy_count <= 0 else min(100, round(available / proxy_count * 100))
    speed_percent = 0 if speed_done <= 0 else min(100, round(speed_pass / speed_done * 100))
    return jsonify(
        {
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "checked_label": datetime.now().strftime("%H:%M:%S"),
            "engine": {
                "active": engine["active"],
                "mode": engine["mode"],
                "status": engine["status"],
                "status_tone": engine["status_tone"],
                "status_detail": engine["status_detail"],
                "active_label": engine["active_label"],
                "reason": engine["reason"],
                "default_output_count": engine["default_output_count"],
                "default_output_label": engine["default_output_label"],
                "asset_pool_count": engine["asset_pool_count"],
                "min_output_nodes": engine["min_output_nodes"],
                "quality": engine["quality"],
            },
            "assets": {
                "total": len(all_rows),
                "filtered": len(filtered_rows),
                "upstream_total": upstream_all_count,
                "upstream_subscription": upstream_all_count - upstream_filtered_count,
                "upstream_filtered": upstream_filtered_count,
                "proxy_ok": upstream_proxy_ok_count,
                "subscription_count": engine["default_output_count"],
            },
            "subs_check": {
                "ok": bool(status.get("ok")),
                "node_count": safe_int(status.get("node_count")),
                "message": status.get("message", ""),
                "quality": engine["quality"],
            },
            "api": {
                "ok": bool(api.get("ok")),
                "checking": bool(api.get("checking")),
                "label": "检测中" if api.get("checking") else "已完成" if api.get("ok") else "未连接",
                "proxy_count": proxy_count,
                "progress": progress,
                "available": available,
                "speed_done": speed_done,
                "speed_pass": speed_pass,
                "alive_percent": alive_percent,
                "available_percent": available_percent,
                "speed_percent": speed_percent,
                "message": api.get("message", ""),
            },
        }
    )


@app.route("/admin/subs-check")
@login_required
def subs_check_admin():
    engine = subscription_engine_state()
    mode_labels = {"local": "全量节点池", "balanced": "自动优选", "strict": "严格优选"}
    return render_template(
        "admin/subs_check.html",
        page_title="订阅策略",
        status=subs_check_status(),
        api=subs_check_api_status(),
        logs=subs_check_api_logs(),
        runs=list_subs_check_runs(12),
        engine=engine,
        engine_mode_label=mode_labels.get(engine["mode"], engine["mode"]),
        config=subs_check_config_summary(),
        enabled=SUBS_CHECK_SUBSCRIPTION_ENABLED,
        paths={
            "clash": SUBS_CHECK_CLASH_PATH,
            "v2ray": SUBS_CHECK_V2RAY_PATH,
            "surge": SUBS_CHECK_SURGE_PATH or "未配置，回退本地输出",
            "qx": SUBS_CHECK_QX_PATH or "未配置，回退本地输出",
        },
    )


@app.route("/admin/subs-check/config", methods=["POST"])
@login_required
def update_subs_check_config_route():
    try:
        save_subs_check_config_from_form(request.form)
        audit("更新 subs-check 配置", "subs-check", "", "更新过滤、媒体检测、通知和 UA")
        if request.form.get("trigger_after_save") == "1":
            payload = subs_check_api_request("/api/trigger-check", method="POST")
            record_subs_check_run("保存配置并重检", "已触发", str(payload.get("message") or "已触发检测"), 0, True)
            flash("subs-check 配置已保存，并已触发立即检测。")
        else:
            flash("subs-check 配置已保存。容器会自动重新加载配置，下一轮检测生效。")
    except Exception as exc:
        record_subs_check_run("保存配置", "失败", str(exc))
        flash(f"subs-check 配置保存失败：{str(exc)[:160]}")
    return redirect(request.referrer or url_for("nodes_admin"))


@app.route("/admin/subscription-engine", methods=["POST"])
@login_required
def update_subscription_engine_route():
    mode = request.form.get("mode", "balanced").strip().lower()
    if mode not in {"local", "balanced", "strict"}:
        mode = "balanced"
    min_nodes_raw = request.form.get("min_output_nodes", str(SUBS_CHECK_MIN_OUTPUT_NODES)).strip()
    try:
        min_nodes = int(min_nodes_raw)
    except ValueError:
        min_nodes = SUBS_CHECK_MIN_OUTPUT_NODES
    min_nodes = max(0, min(min_nodes, 10000))
    set_setting("subscription_engine_mode", mode)
    set_setting("subs_check_min_output_nodes", str(min_nodes))
    labels = {"local": "全量节点池", "balanced": "自动优选", "strict": "严格优选"}
    audit("修改订阅策略", "settings", "subscription_engine", f"{labels.get(mode, mode)} · 优选阈值 {min_nodes}")
    flash(f"订阅策略已切换为：{labels.get(mode, mode)}。优选最低节点数：{min_nodes}。")
    next_url = request.form.get("next") or request.referrer or url_for("nodes_admin")
    if not str(next_url).startswith("/"):
        next_url = url_for("nodes_admin")
    return redirect(next_url)


@app.route("/admin/public-subscription", methods=["POST"])
@login_required
def update_public_subscription_route():
    enabled = "1" if request.form.get("public_subscription_enabled") == "1" else "0"
    set_setting("public_subscription_enabled", enabled)
    audit("修改公开订阅入口", "settings", "public_subscription_enabled", "开启" if enabled == "1" else "关闭")
    flash("公开订阅入口已开启。" if enabled == "1" else "公开订阅入口已关闭，会员专属订阅不受影响。")
    next_url = request.form.get("next") or request.referrer or url_for("admin_checks")
    if not str(next_url).startswith("/"):
        next_url = url_for("admin_checks")
    return redirect(next_url)


@app.route("/admin/subs-check/trigger", methods=["POST"])
@login_required
def trigger_subs_check_route():
    try:
        payload = subs_check_api_request("/api/trigger-check", method="POST")
        status = subs_check_api_status()
        message = str(payload.get("message") or "已触发检测")
        record_subs_check_run("立即重检", "已触发", message, status.get("proxy_count", 0), status.get("checking", False))
        audit("触发 subs-check 检测", "subs-check", "", message)
        flash("已触发 subs-check 立即检测。")
    except Exception as exc:
        record_subs_check_run("立即重检", "失败", str(exc))
        flash(f"触发 subs-check 检测失败：{str(exc)[:180]}")
    return redirect(request.referrer or url_for("nodes_admin"))


@app.route("/admin/subs-check/import", methods=["POST"])
@login_required
def import_subs_check_output_route():
    status = subs_check_status()
    if not status.get("ok") or not status.get("node_count"):
        flash(f"优选输出不可导入：{status.get('message') or '没有可用节点'}")
        return redirect(url_for("nodes_admin"))
    upstream_id = upsert_subs_check_upstream()
    ok, message, count = sync_upstream(upstream_id)
    if ok:
        marked = mark_upstream_nodes_proxy_ok(upstream_id)
        enriched = enrich_subs_check_upstream_metadata(upstream_id)
        record_subs_check_run("导入优选结果", "导入成功", f"{count} 个节点，标记 {marked} 个真可用，元数据 {enriched} 条", count)
        audit("导入 subs-check 优选", "upstream", upstream_id, f"{count} 个节点，标记 {marked} 个真可用，元数据 {enriched} 条")
        flash(f"已把 subs-check 优选输出导入节点池：{count} 个节点，已同步 {enriched} 条媒体/速度元数据。")
        return redirect(url_for("nodes_admin", q=SUBS_CHECK_IMPORT_NAME))
    audit("导入 subs-check 优选失败", "upstream", upstream_id, message)
    record_subs_check_run("导入优选结果", "失败", message)
    flash(f"优选输出导入失败：{message}")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/traffic")
@login_required
def traffic_admin():
    return render_template("admin/traffic.html", **traffic_context())


@app.route("/admin/users")
@login_required
def users_admin():
    return render_template("admin/users.html", **users_context())


@app.route("/admin/account")
@login_required
def account_admin():
    return render_template(
        "admin/account.html",
        page_title="账号安全",
        username=current_admin_user(),
        default_password=is_default_password(),
        checks=system_checks(),
    )


@app.route("/admin/plans")
@login_required
def plans_admin():
    return render_template("admin/plans.html", page_title="套餐方案", plans=list_plans())


@app.route("/admin/plans", methods=["POST"])
@login_required
def create_plan():
    name = request.form.get("name", "").strip() or "未命名套餐"
    try:
        days = max(0, int(request.form.get("days", "30")))
    except ValueError:
        days = 30
    total_bytes = parse_gb(request.form.get("total_gb", "0"))
    note = request.form.get("note", "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO plans(name, days, total_bytes, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, days, total_bytes, note, now, now),
            )
        audit("创建套餐", "plan", name, f"{name} · {days} 天 · {format_bytes(total_bytes) if total_bytes else '不限'}")
        flash("套餐模板已创建。")
    except sqlite3.IntegrityError:
        flash("套餐名已存在，请换一个。")
    return redirect(url_for("plans_admin"))


@app.route("/admin/plans/<int:plan_id>/delete", methods=["POST"])
@login_required
def delete_plan(plan_id: int):
    with db() as conn:
        conn.execute("DELETE FROM plans WHERE id = ?", (plan_id,))
    audit("删除套餐", "plan", plan_id, "删除套餐模板")
    flash("套餐模板已删除。")
    return redirect(url_for("plans_admin"))


@app.route("/admin/users", methods=["POST"])
@login_required
def create_subscriber():
    name = request.form.get("name", "").strip() or "未命名用户"
    expire_at = request.form.get("expire_at", "").strip()
    total_bytes = parse_gb(request.form.get("total_gb", "0"))
    plan = get_plan(request.form.get("plan_id", ""))
    if plan:
        expire_at = expire_at or add_days(plan["days"])
        total_bytes = plan["total_bytes"]
    token = new_subscriber_token()
    traffic_key = request.form.get("traffic_key", "").strip() or token
    note = request.form.get("note", "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    backup_subscribers()
    try:
        with db() as conn:
            cur = conn.execute(
                """
                INSERT INTO subscribers(name, token, traffic_key, enabled, expire_at, total_bytes, used_bytes, note, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?, 0, ?, ?, ?)
                """,
                (name, token, traffic_key, expire_at, total_bytes, note, now, now),
            )
            user_id = cur.lastrowid
        audit("创建用户", "user", name, f"{name} · 到期 {expire_at or '不限'} · 总量 {format_bytes(total_bytes) if total_bytes else '不限'}")
        flash("用户已创建，专属订阅链接已生成。")
        return redirect(url_for("subscriber_detail", user_id=user_id, issued=1))
    except sqlite3.IntegrityError:
        flash("流量识别名已经被其他用户使用，请换一个。")
    return redirect(url_for("users_admin"))


@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
@login_required
def update_subscriber(user_id: int):
    name = request.form.get("name", "").strip() or "未命名用户"
    expire_at = request.form.get("expire_at", "").strip()
    total_bytes = parse_gb(request.form.get("total_gb", "0"))
    used_bytes = parse_gb(request.form.get("used_gb", "0"))
    traffic_key = request.form.get("traffic_key", "").strip()
    note = request.form.get("note", "").strip()
    enabled = 1 if request.form.get("enabled") == "1" else 0
    now = datetime.now().isoformat(timespec="seconds")
    backup_subscribers()
    try:
        with db() as conn:
            conn.execute(
                """
                UPDATE subscribers
                SET name = ?, traffic_key = ?, enabled = ?, expire_at = ?, total_bytes = ?, used_bytes = ?, note = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, traffic_key, enabled, expire_at, total_bytes, used_bytes, note, now, user_id),
            )
        audit("修改用户", "user", user_id, f"{name} · 状态 {'启用' if enabled else '停用'} · 到期 {expire_at or '不限'}")
        flash("用户套餐已保存。")
    except sqlite3.IntegrityError:
        flash("流量识别名已经被其他用户使用，保存失败。")
    return redirect(url_for("subscriber_detail", user_id=user_id))


@app.route("/admin/users/<int:user_id>/reset-token", methods=["POST"])
@login_required
def reset_subscriber_token(user_id: int):
    now = datetime.now().isoformat(timespec="seconds")
    backup_subscribers()
    with db() as conn:
        conn.execute("UPDATE subscribers SET token = ?, updated_at = ? WHERE id = ?", (new_subscriber_token(), now, user_id))
    audit("重置订阅", "user", user_id, "旧订阅链接已失效")
    flash("订阅链接已重置，旧链接已经失效。")
    return redirect(url_for("users_admin"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_subscriber(user_id: int):
    backup_subscribers()
    with db() as conn:
        conn.execute("DELETE FROM subscribers WHERE id = ?", (user_id,))
    audit("删除用户", "user", user_id, "删除用户并自动备份用户列表")
    flash("用户已删除。")
    return redirect(url_for("users_admin"))


@app.route("/admin/users/<int:user_id>")
@login_required
def subscriber_detail(user_id: int):
    user = get_subscriber(user_id)
    if not user:
        flash("用户不存在。")
        return redirect(url_for("users_admin"))
    access_checks = [
        {"label": "订阅状态", "ok": subscriber_allowed(user), "detail": user["status"]},
        {"label": "到期时间", "ok": user["expire_days"] is None or user["expire_days"] >= 0, "detail": user["expire_at"] or "不限"},
        {"label": "流量额度", "ok": user["total_bytes"] == 0 or user["used_bytes"] < user["total_bytes"], "detail": f"{user['used_label']} / {user['total_label']}"},
        {"label": "流量识别名", "ok": bool(user.get("traffic_key")), "detail": user.get("traffic_key") or "未设置"},
    ]
    return render_template(
        "admin/user_detail.html",
        page_title="用户详情",
        user=user,
        base=public_base_url(),
        access_checks=access_checks,
        issued=request.args.get("issued") == "1",
    )


@app.route("/admin/users/<int:user_id>/qr/<fmt>")
@login_required
def subscriber_qr(user_id: int, fmt: str):
    user = get_subscriber(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    if fmt not in user["links"]:
        fmt = "clash"
    url = public_base_url() + user["links"][fmt]
    return Response(make_qr_svg(url), content_type="image/svg+xml; charset=utf-8")


@app.route("/admin/users/<int:user_id>/quick", methods=["POST"])
@login_required
def subscriber_quick_action(user_id: int):
    user = get_subscriber(user_id)
    if not user:
        flash("用户不存在。")
        return redirect(url_for("users_admin"))
    action = request.form.get("action", "")
    now = datetime.now().isoformat(timespec="seconds")
    backup_subscribers()
    audit_action = ""
    audit_message = ""
    with db() as conn:
        if action == "extend":
            try:
                days = max(0, int(request.form.get("add_days", "0")))
            except ValueError:
                days = 0
            base = datetime.strptime(user["expire_at"], "%Y-%m-%d") if user["expire_at"] else datetime.now()
            conn.execute("UPDATE subscribers SET expire_at = ?, updated_at = ? WHERE id = ?", (add_days(days, base), now, user_id))
            audit_action = "延长用户"
            audit_message = f"延长 {days} 天"
            flash(f"已延长 {days} 天。")
        elif action == "add_traffic":
            add_bytes = parse_gb(request.form.get("add_gb", "0"))
            conn.execute("UPDATE subscribers SET total_bytes = total_bytes + ?, updated_at = ? WHERE id = ?", (add_bytes, now, user_id))
            audit_action = "增加流量"
            audit_message = f"增加 {format_bytes(add_bytes)}"
            flash(f"已增加 {bytes_to_gb(add_bytes)} GB 流量。")
        elif action == "reset_used":
            conn.execute("UPDATE subscribers SET used_bytes = 0, updated_at = ? WHERE id = ?", (now, user_id))
            audit_action = "清零流量"
            audit_message = "已用流量清零"
            flash("已清零已用流量。")
    if audit_action:
        audit(audit_action, "user", user_id, audit_message)
    return redirect(url_for("subscriber_detail", user_id=user_id))


@app.route("/admin/nodes", methods=["POST"])
@login_required
def save_nodes():
    nodes = clean_lines(request.form.get("nodes", ""))
    replace_nodes(nodes)
    audit("保存节点", "nodes", "", f"保存 {len(nodes)} 个节点")
    flash(f"已保存 {len(nodes)} 个节点，订阅已同步。")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/nodes/add", methods=["POST"])
@login_required
def append_nodes():
    nodes = clean_lines(request.form.get("nodes", ""))
    if not nodes:
        flash("没有检测到新节点。")
        return redirect(url_for("nodes_admin"))
    added, skipped = add_nodes(nodes)
    audit("追加节点", "nodes", "", f"新增 {added} 个，跳过 {skipped} 个重复")
    flash(f"已追加 {added} 个节点，跳过 {skipped} 个重复节点。")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/upstreams", methods=["POST"])
@login_required
def create_upstream():
    upload = request.files.get("file")
    uploaded_stem = Path(upload.filename).stem.strip() if upload and upload.filename else ""
    name = request.form.get("name", "").strip() or uploaded_stem or "未命名订阅"
    url = request.form.get("url", "").strip()
    prefix = request.form.get("prefix", "").strip()
    only_nodes = 1 if request.form.get("only_nodes", "1") == "1" else 0
    try:
        update_interval = max(1, int(request.form.get("update_interval_minutes", "60")))
    except ValueError:
        update_interval = 60
    pasted_content = request.form.get("content", "").strip()
    uploaded_content = ""
    if upload and upload.filename:
        uploaded_content = upload.read(5 * 1024 * 1024 + 1).decode("utf-8", errors="replace")
        if len(uploaded_content.encode("utf-8")) > 5 * 1024 * 1024:
            flash("上传文件太大，最多支持 5MB。")
            return redirect(url_for("nodes_admin"))
    content = uploaded_content.strip() or pasted_content
    source_type = "file" if content else "url"
    if source_type == "url" and not url.startswith(("http://", "https://")):
        flash("请填写 http:// 或 https:// 开头的订阅链接，或者上传订阅文件。")
        return redirect(url_for("nodes_admin"))
    if source_type == "file":
        try:
            parsed = parse_subscription_text(content)
        except Exception as exc:
            parsed = []
            flash(f"上传内容解析失败：{exc}")
        if not parsed:
            flash("上传内容里没有解析到支持的节点。")
            return redirect(url_for("nodes_admin"))
        if not url:
            url = f"upload://{secrets.token_urlsafe(8)}"
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO upstreams(name, url, enabled, prefix, source_type, content, update_interval_minutes, only_nodes, created_at, updated_at)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name, url, prefix, source_type, content, update_interval, only_nodes, now, now),
        )
        upstream_id = cur.lastrowid
    ok, message, count = sync_upstream(upstream_id)
    audit("添加上游订阅", "upstream", upstream_id, f"{name} · {count} 个节点" if ok else f"{name} · {message}")
    flash(f"上游订阅已添加，{'同步成功 ' + str(count) + ' 个节点' if ok else '同步失败：' + message}")
    if ok:
        first_asset_key = ""
        with db() as conn:
            row = conn.execute("SELECT id, upstream_id, raw FROM upstream_nodes WHERE upstream_id = ? ORDER BY id LIMIT 1", (upstream_id,)).fetchone()
            if row:
                first_asset_key = upstream_asset_key(dict(row))
        return redirect(url_for("nodes_admin", q=name, asset_key=first_asset_key))
    return redirect(url_for("nodes_admin"))


@app.route("/admin/upstreams/sync", methods=["POST"])
@login_required
def sync_all_upstreams_route():
    ok, total = sync_enabled_upstreams()
    audit("同步全部上游", "upstream", "", f"{ok}/{total} 个成功")
    flash(f"上游订阅同步完成：{ok}/{total} 个成功。")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/upstreams/<int:upstream_id>/sync", methods=["POST"])
@login_required
def sync_upstream_route(upstream_id: int):
    ok, message, count = sync_upstream(upstream_id)
    audit("同步上游订阅", "upstream", upstream_id, f"{count} 个节点" if ok else message)
    flash(f"同步成功：{count} 个节点。" if ok else f"同步失败：{message}")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/upstreams/<int:upstream_id>/toggle", methods=["POST"])
@login_required
def toggle_upstream(upstream_id: int):
    upstream = get_upstream(upstream_id)
    if not upstream:
        flash("上游订阅不存在。")
        return redirect(url_for("nodes_admin"))
    enabled = 0 if upstream["enabled"] else 1
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute("UPDATE upstreams SET enabled = ?, updated_at = ? WHERE id = ?", (enabled, now, upstream_id))
    audit("切换上游订阅", "upstream", upstream_id, "启用" if enabled else "停用")
    flash("上游订阅已启用。" if enabled else "上游订阅已停用。")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/upstreams/<int:upstream_id>/rename", methods=["POST"])
@login_required
def rename_upstream(upstream_id: int):
    upstream = get_upstream(upstream_id)
    if not upstream:
        flash("上游订阅不存在。")
        return redirect(url_for("nodes_admin"))
    name = request.form.get("name", "").strip()
    if not name:
        flash("订阅源名称不能为空。")
        return redirect(url_for("nodes_admin", q=upstream["name"]))
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute("UPDATE upstreams SET name = ?, updated_at = ? WHERE id = ?", (name, now, upstream_id))
    audit("重命名上游订阅", "upstream", upstream_id, f"{upstream['name']} => {name}")
    flash("订阅源名称已更新。")
    return redirect(url_for("nodes_admin", q=name))


@app.route("/admin/upstreams/<int:upstream_id>/update", methods=["POST"])
@login_required
def update_upstream(upstream_id: int):
    upstream = get_upstream(upstream_id)
    if not upstream:
        flash("上游订阅不存在。")
        return redirect(url_for("nodes_admin", _anchor="upstreams"))
    if str(upstream["name"] or "").strip() == SUBS_CHECK_IMPORT_NAME:
        flash("这是系统维护的 subs-check 输出源，不能手动修改链接。")
        return redirect(url_for("nodes_admin", _anchor="upstreams"))

    name = request.form.get("name", "").strip()
    prefix = request.form.get("prefix", "").strip()
    only_nodes = 1 if request.form.get("only_nodes") == "1" else 0
    try:
        update_interval = max(1, min(10080, int(request.form.get("update_interval_minutes", "60"))))
    except ValueError:
        update_interval = 60
    if not name:
        flash("订阅源名称不能为空。")
        return redirect(url_for("nodes_admin", _anchor="upstreams"))

    source_type = str(upstream["source_type"] or "url")
    old_url = str(upstream["url"] or "")
    url = request.form.get("url", "").strip() if source_type == "url" else old_url
    if source_type == "url" and not url.startswith(("http://", "https://")):
        flash("订阅链接必须以 http:// 或 https:// 开头，原配置未修改。")
        return redirect(url_for("nodes_admin", _anchor="upstreams"))

    with db() as conn:
        cached_count = int(conn.execute("SELECT COUNT(*) FROM upstream_nodes WHERE upstream_id = ?", (upstream_id,)).fetchone()[0])
        conn.execute(
            """
            UPDATE upstreams
            SET name = ?, url = ?, prefix = ?, update_interval_minutes = ?, only_nodes = ?, updated_at = ?
            WHERE id = ?
            """,
            (name, url, prefix, update_interval, only_nodes, datetime.now().isoformat(timespec="seconds"), upstream_id),
        )

    url_changed = old_url != url
    change_summary = f"名称 {upstream['name']} => {name}"
    if url_changed:
        change_summary += " · 订阅链接已更新"
    if request.form.get("sync_after_save") == "1":
        ok, message, count = sync_upstream(upstream_id)
        if ok:
            audit("编辑上游订阅", "upstream", upstream_id, f"{change_summary} · 同步 {count} 个节点")
            flash(f"订阅源已保存并同步成功：{count} 个节点。")
        else:
            audit("编辑上游订阅", "upstream", upstream_id, f"{change_summary} · 同步失败：{message}")
            flash(f"订阅源已保存，但同步失败：{message}。旧缓存 {cached_count} 个节点仍保留。")
    else:
        audit("编辑上游订阅", "upstream", upstream_id, f"{change_summary} · 未立即同步")
        flash("订阅源配置已保存，尚未重新同步。")
    return redirect(url_for("nodes_admin", q=name, _anchor="upstreams"))


@app.route("/admin/upstreams/<int:upstream_id>/delete", methods=["POST"])
@login_required
def delete_upstream(upstream_id: int):
    upstream = get_upstream(upstream_id)
    if not upstream:
        flash("上游订阅不存在。")
        return redirect(url_for("nodes_admin"))
    with db() as conn:
        conn.execute("DELETE FROM upstreams WHERE id = ?", (upstream_id,))
    audit("删除上游订阅", "upstream", upstream_id, upstream["name"])
    flash("上游订阅已删除，缓存节点已移除。")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/password", methods=["POST"])
@login_required
def change_password():
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if len(new_password) < 4:
        flash("新密码至少 4 位。")
    elif new_password != confirm_password:
        flash("两次输入的新密码不一致。")
    elif update_admin_password(old_password, new_password):
        audit("修改密码", "admin", current_admin_user(), "后台密码已修改")
        flash("后台密码已修改。")
    else:
        flash("旧密码不对，密码没有修改。")
    next_url = request.form.get("next") or request.referrer or url_for("admin_checks")
    return redirect(next_url)


@app.route("/admin/return-test-target", methods=["POST"])
@login_required
def update_return_test_target():
    host = request.form.get("return_test_host", "").strip()
    port_text = request.form.get("return_test_port", "443").strip() or "443"
    try:
        port = int(port_text)
    except ValueError:
        port = 0
    if host and not 1 <= port <= 65535:
        flash("端口必须是 1 到 65535。")
        return redirect(url_for("nodes_admin"))
    set_setting("return_test_host", host)
    set_setting("return_test_port", str(port or 443))
    message = f"测速目标已保存：{host}:{port or 443}" if host else "测速目标已清空，后续会回退测节点入口。"
    audit("修改测速目标", "settings", "return_test_target", message)
    flash(message)
    return redirect(url_for("nodes_admin"))


@app.route("/admin/geo/refresh", methods=["POST"])
@login_required
def refresh_geo_batch():
    all_rows = node_view_rows()
    filters = {
        "q": request.form.get("q", request.args.get("q", "")).strip(),
        "region": request.form.get("region", request.args.get("region", "")).strip(),
        "status": request.form.get("status", request.args.get("status", "")).strip(),
        "protocol": request.form.get("protocol", request.args.get("protocol", "")).strip(),
    }
    rows = filter_nodes(all_rows, filters)
    hosts = []
    for row in rows:
        host = normalize_host(row.get("endpoint_host") or "")
        if host and host != "未知" and host not in hosts:
            hosts.append(host)
        if len(hosts) >= GEO_REFRESH_LIMIT:
            break
    ok = 0
    failed = 0
    for host in hosts:
        geo = get_geo_for_host(host, refresh=True)
        if geo.get("status") == "ok":
            ok += 1
        else:
            failed += 1
    audit("刷新节点地理位置", "geo", "batch", f"处理 {len(hosts)} 个入口，成功 {ok} 个，异常 {failed} 个")
    flash(f"地理识别完成：处理 {len(hosts)} 个入口，成功 {ok} 个，异常 {failed} 个。")
    return redirect(url_for("nodes_admin", **{key: value for key, value in filters.items() if value}))


@app.route("/admin/node-assets/<asset_key>/geo-refresh", methods=["POST"])
@login_required
def refresh_node_asset_geo(asset_key: str):
    asset = get_node_asset(asset_key)
    if not asset:
        flash("节点资产不存在。")
        return redirect(url_for("nodes_admin"))
    endpoint = node_endpoint(asset["raw"])
    if not endpoint or not endpoint[0]:
        flash("无法解析节点入口地址。")
        return redirect(url_for("nodes_admin", asset_key=asset_key))
    geo = get_geo_for_host(endpoint[0], refresh=True)
    if geo.get("status") == "ok":
        flash(f"地理识别完成：{geo_country_label(geo)} · {geo.get('resolved_ip') or endpoint[0]}")
    else:
        flash(f"地理识别异常：{geo.get('error') or geo.get('status') or '未知错误'}")
    audit("刷新节点地理位置", "node_asset", asset_key, f"{endpoint[0]} => {geo.get('status')}")
    return redirect(url_for("nodes_admin", asset_key=asset_key))


@app.route("/admin/nodes/<int:node_id>/geo-refresh", methods=["POST"])
@login_required
def refresh_node_geo(node_id: int):
    return refresh_node_asset_geo(f"manual:{node_id}")


@app.route("/admin/nodes/<int:node_id>/rename", methods=["POST"])
@login_required
def rename_node(node_id: int):
    name = request.form.get("display_name", "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute("UPDATE nodes SET display_name = ?, updated_at = ? WHERE id = ?", (name, now, node_id))
    sync_nodes_file()
    audit("节点改名", "node", node_id, name)
    flash("节点显示名已更新，订阅已同步。")
    return redirect(url_for("nodes_admin", node_id=node_id))


@app.route("/admin/nodes/<int:node_id>/delete", methods=["POST"])
@login_required
def delete_node(node_id: int):
    backup_current_nodes()
    with db() as conn:
        conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    sync_nodes_file()
    audit("删除节点", "node", node_id, "删除节点并同步订阅")
    flash("节点已删除，订阅已同步。")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/export")
@login_required
def export_nodes():
    return Response("\n".join(load_nodes()) + "\n", content_type="text/plain; charset=utf-8")


@app.route("/admin/export/users.csv")
@login_required
def export_subscribers():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "name", "status", "traffic_key", "enabled", "expire_at", "total_gb", "used_gb", "note", "clash_url", "v2ray_url"])
    base = public_base_url()
    for user in list_subscribers():
        writer.writerow(
            [
                user["id"],
                user["name"],
                user["status"],
                user["traffic_key"],
                user["enabled"],
                user["expire_at"],
                user["total_gb"],
                user["used_gb"],
                user["note"],
                base + user["links"]["clash"],
                base + user["links"]["v2ray"],
            ]
        )
    return Response(
        output.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=subscribers.csv"},
    )


@app.route("/admin/export/nodes.csv")
@login_required
def export_nodes_csv():
    filters = {
        "q": request.args.get("q", "").strip(),
        "region": request.args.get("region", "").strip(),
        "status": request.args.get("status", "").strip(),
        "protocol": request.args.get("protocol", "").strip(),
    }
    rows = filter_nodes(node_view_rows(), filters)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "asset_key", "name", "source", "upstream", "protocol", "status", "endpoint_host", "endpoint_port",
        "resolved_ip", "country", "region", "asn", "org", "latency_ms", "monitor_reported_at",
        "cpu_percent", "memory_percent", "inbound_bps", "outbound_bps", "connections",
    ])
    for row in rows:
        monitor = row.get("monitor") or {}
        writer.writerow([
            row.get("asset_key", ""),
            row.get("display", ""),
            row.get("source_label", ""),
            row.get("upstream_name", ""),
            row.get("protocol", ""),
            row.get("status_label", ""),
            row.get("endpoint_host", ""),
            row.get("endpoint_port", ""),
            row.get("resolved_ip", ""),
            row.get("country_label", ""),
            row.get("region", ""),
            row.get("asn", ""),
            row.get("org", ""),
            row.get("last_latency_ms") or "",
            monitor.get("reported_at", ""),
            monitor.get("cpu_percent", ""),
            monitor.get("memory_percent", ""),
            monitor.get("inbound_bps", ""),
            monitor.get("outbound_bps", ""),
            monitor.get("connections", ""),
        ])
    return Response(
        "\ufeff" + output.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=nodes.csv"},
    )


@app.route("/admin/export/traffic.csv")
@login_required
def export_traffic_csv():
    range_key = normalized_traffic_range(request.args.get("range", "").strip())
    risk = request.args.get("risk", "").strip()
    protocol = request.args.get("protocol", "").strip()
    q = request.args.get("q", "").strip()
    total = count_traffic_events(risk=risk, protocol=protocol, q=q, range_key=range_key)
    export_limit = max(1, EXPORT_MAX_ROWS)
    rows = query_traffic_events(export_limit, risk=risk, protocol=protocol, q=q, range_key=range_key)
    truncated = total > export_limit
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "traffic_key", "user_name", "source_ip", "node", "protocol", "upload_bytes", "download_bytes", "risk", "action", "message"])
    for row in rows:
        writer.writerow([
            row.get("id", ""),
            row.get("created_at", ""),
            row.get("traffic_key", ""),
            row.get("user_name", ""),
            row.get("source_ip", ""),
            row.get("node", ""),
            row.get("protocol", ""),
            row.get("upload_bytes", 0),
            row.get("download_bytes", 0),
            row.get("risk", ""),
            row.get("action", ""),
            row.get("message", ""),
        ])
    headers = {"Content-Disposition": "attachment; filename=traffic-events.csv"}
    if truncated:
        headers["X-Export-Truncated"] = "true"
        headers["X-Export-Total-Rows"] = str(total)
        headers["X-Export-Max-Rows"] = str(export_limit)
    return Response(
        "\ufeff" + output.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers=headers,
    )


@app.route("/admin/export/report.json")
@login_required
def export_report_json():
    return jsonify(report_payload())


@app.route("/admin/export/database")
@login_required
def download_database_backup():
    target = create_database_backup()
    audit("下载备份", "database", target.name, "下载当前数据库备份")
    return send_file(target, as_attachment=True, download_name=target.name, mimetype="application/octet-stream")


@app.route("/admin/backups")
@login_required
def backups_admin():
    return render_template("admin/backups.html", page_title="备份恢复", backups=list_database_backups(), backup_status=backup_status())


@app.route("/admin/backups/create", methods=["POST"])
@login_required
def create_backup_route():
    target = create_database_backup()
    audit("创建备份", "database", target.name, "手动创建数据库备份")
    flash(f"数据库备份已创建：{target.name}")
    return redirect(url_for("backups_admin"))


@app.route("/admin/backups/drill", methods=["POST"])
@login_required
def backup_drill_route():
    result = run_backup_drill()
    audit("备份恢复演练", "database", result["backup"], result["message"])
    flash("备份演练通过：" + result["message"] if result["ok"] else "备份演练失败：" + result["message"])
    return redirect(url_for("backups_admin"))


@app.route("/admin/logs")
@login_required
def audit_logs_admin():
    page, per_page = pagination_args(50, 200)
    pager = paginate_items(list_all_audit_logs(), page, per_page)
    return render_template("admin/logs.html", page_title="审计日志", logs=pager["items"], pager=pager)


@app.route("/admin/search")
@login_required
def admin_search():
    q = request.args.get("q", "").strip()
    return render_template("admin/search.html", page_title="全局搜索", results=search_context(q))


@app.route("/admin/checks")
@login_required
def admin_checks():
    return render_template("admin/checks.html", page_title="上线检查", checks=system_checks())


@app.route("/admin/search.json")
@login_required
def admin_search_json():
    q = request.args.get("q", "").strip()
    results = search_context(q)
    return jsonify(
        {
            "q": results["q"],
            "total": results["total"],
            "groups": {
                "nodes": [
                    {
                        "title": row["display"],
                        "meta": f"{row['source_label']} · {row['endpoint_host']} · {row['country_label']}",
                        "href": url_for("nodes_admin", asset_key=row["asset_key"], q=results["q"]),
                    }
                    for row in results["nodes"][:5]
                ],
                "users": [
                    {
                        "title": user["name"],
                        "meta": f"{user['status']} · {user.get('traffic_key') or '未设置识别名'}",
                        "href": url_for("subscriber_detail", user_id=user["id"]),
                    }
                    for user in results["users"][:5]
                ],
                "events": [
                    {
                        "title": item.get("message") or item.get("action") or "流量事件",
                        "meta": f"{item.get('source_ip') or '-'} · {item.get('node') or '-'}",
                        "href": url_for("traffic_admin", q=results["q"]),
                    }
                    for item in results["events"][:5]
                ],
                "logs": [
                    {
                        "title": log["action"],
                        "meta": f"{log['target_type']} {log['target_id']} · {log['actor']}",
                        "href": url_for("audit_logs_admin", q=results["q"]),
                    }
                    for log in results["logs"][:5]
                ],
                "upstreams": [
                    {
                        "title": item["name"],
                        "meta": f"{item['verify_status']} · {item['verify_label']}",
                        "href": url_for("nodes_admin", q=item["name"]),
                    }
                    for item in results["upstreams"][:5]
                ],
            },
            "search_url": url_for("admin_search", q=results["q"]),
        }
    )


@app.route("/admin/backups/<name>/restore", methods=["POST"])
@login_required
def restore_backup(name: str):
    if restore_database_backup(name):
        init_db()
        audit("恢复备份", "database", name, "数据库已恢复，恢复前已自动备份当前库")
        flash("数据库已恢复，请重新检查节点和用户数据。")
    else:
        flash("备份文件无效或不存在。")
    return redirect(url_for("backups_admin"))


def node_endpoint(raw: str) -> tuple[str, int] | None:
    try:
        if raw.startswith("vmess://"):
            info = json.loads(b64decode_text(raw[8:]))
            return info.get("add", ""), int(info.get("port", 443))
        if raw.startswith("ssr://"):
            decoded = b64decode_text(raw[6:])
            main = decoded.split("/?", 1)[0].split(":")
            return main[0], int(main[1])
        if raw.startswith("ss://"):
            payload = raw[5:]
            if "@" not in payload:
                return node_endpoint("ss://" + b64decode_text(payload))
            parsed = urlparse(raw)
            return parsed.hostname or "", int(parsed.port or 8388)
        if raw.startswith(("vless://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://")):
            parsed = urlparse(raw)
            return parsed.hostname or "", int(parsed.port or 443)
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            return parsed.hostname or "", int(parsed.port or (443 if parsed.scheme == "https" else 80))
    except Exception:
        return None
    return None


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def sing_box_available() -> bool:
    return bool(SING_BOX_PATH) and Path(SING_BOX_PATH).exists()


def curl_available() -> bool:
    return bool(shutil.which("curl"))


def sing_box_outbound(raw: str) -> dict:
    if raw.startswith("vmess://"):
        try:
            info = json.loads(b64decode_text(raw[8:]))
        except Exception as exc:
            raise ValueError(f"VMess 解析失败：{exc}") from exc
        host = str(info.get("add") or "").strip()
        user = str(info.get("id") or "").strip()
        try:
            port = int(info.get("port") or 443)
        except (TypeError, ValueError):
            port = 443
        if not host or not user:
            raise ValueError("节点缺少地址或凭据")
        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": user,
            "security": str(info.get("scy") or info.get("security") or "auto"),
            "alter_id": int(info.get("aid") or 0),
        }
        tls_enabled = str(info.get("tls") or "").lower() == "tls"
        if tls_enabled:
            tls = {"enabled": True}
            sni = str(info.get("sni") or info.get("peer") or info.get("host") or "").strip()
            if sni:
                tls["server_name"] = sni
            tls["insecure"] = str(info.get("allowInsecure") or info.get("insecure") or "1").lower() in {"1", "true", "yes"}
            outbound["tls"] = tls
        transport_type = str(info.get("net") or "tcp").lower()
        if transport_type and transport_type not in {"tcp", "none"}:
            transport = {"type": transport_type}
            if transport_type == "ws":
                transport["path"] = str(info.get("path") or "/")
                ws_host = str(info.get("host") or "").strip()
                if ws_host:
                    transport["headers"] = {"Host": ws_host}
            elif transport_type == "http":
                path = str(info.get("path") or "/")
                http_host = str(info.get("host") or "").strip()
                transport["path"] = path
                if http_host:
                    transport["host"] = [http_host]
            elif transport_type == "grpc":
                transport["service_name"] = str(info.get("path") or "")
            outbound["transport"] = transport
        return outbound

    parsed = urlparse(raw)
    params = parse_qs(parsed.query)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = int(parsed.port or (80 if scheme == "http" else 443))
    user = unquote(parsed.username or "")
    if scheme in {"http", "https"}:
        outbound = {
            "type": "http",
            "tag": "proxy",
            "server": host,
            "server_port": port,
        }
        if user:
            outbound["username"] = user
        password = unquote(parsed.password or "")
        if password:
            outbound["password"] = password
        if scheme == "https" or str((params.get("tls") or [""])[0]).lower() in {"1", "true", "yes"}:
            outbound["tls"] = {
                "enabled": True,
                "insecure": str((params.get("allowInsecure") or params.get("insecure") or ["0"])[0]).lower() in {"1", "true", "yes"},
            }
        return outbound
    if not host or not user:
        raise ValueError("节点缺少地址或凭据")
    sni = (params.get("sni") or params.get("peer") or params.get("host") or [""])[0]
    security = (params.get("security") or [""])[0]
    tls_enabled = scheme == "trojan" or security == "tls" or bool(sni)
    tls = {"enabled": tls_enabled}
    if tls_enabled:
        if sni:
            tls["server_name"] = sni
        alpn = (params.get("alpn") or [""])[0]
        if alpn:
            tls["alpn"] = [item for item in alpn.split(",") if item]
        insecure = (params.get("allowInsecure") or params.get("insecure") or ["1"])[0]
        tls["insecure"] = str(insecure).lower() in {"1", "true", "yes"}
        fingerprint = (params.get("fp") or params.get("client-fingerprint") or ["chrome"])[0]
        if fingerprint and fingerprint != "none":
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if scheme == "trojan":
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": user,
            "tls": tls,
        }
        transport_type = (params.get("type") or ["tcp"])[0]
        if transport_type == "ws":
            transport = {"type": "ws", "path": (params.get("path") or ["/"])[0]}
            ws_host = (params.get("host") or [""])[0]
            if ws_host:
                transport["headers"] = {"Host": ws_host}
            outbound["transport"] = transport
        elif transport_type == "grpc":
            service = (params.get("serviceName") or params.get("service_name") or [""])[0]
            outbound["transport"] = {"type": "grpc", "service_name": service}
        return outbound
    if scheme == "vless":
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": user,
            "tls": tls,
        }
        flow = (params.get("flow") or [""])[0]
        if flow:
            outbound["flow"] = flow
        transport_type = (params.get("type") or ["tcp"])[0]
        if transport_type and transport_type not in {"tcp", ""}:
            transport = {"type": transport_type}
            if transport_type == "ws":
                transport["path"] = (params.get("path") or ["/"])[0]
                ws_host = (params.get("host") or [""])[0]
                if ws_host:
                    transport["headers"] = {"Host": ws_host}
            elif transport_type == "http":
                transport["path"] = (params.get("path") or ["/"])[0]
                http_host = (params.get("host") or [""])[0]
                if http_host:
                    transport["host"] = [http_host]
            elif transport_type == "grpc":
                transport["service_name"] = (params.get("serviceName") or params.get("service_name") or [""])[0]
            outbound["transport"] = transport
        return outbound
    raise ValueError(f"暂不支持 {scheme or 'unknown'} 真测")


def real_proxy_test_node(raw: str, timeout: int = 13) -> tuple[int | None, str]:
    if not sing_box_available():
        return None, "proxy_skipped: sing-box 未安装或未挂载"
    if not curl_available():
        return None, "proxy_skipped: curl 未安装"
    try:
        outbound = sing_box_outbound(raw)
    except ValueError as exc:
        return None, f"proxy_skipped: {exc}"
    port = free_local_port()
    config = {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }
    temp_path = DATA_DIR / f".singbox-proxy-test-{secrets.token_hex(8)}.json"
    temp_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    process = subprocess.Popen(
        [SING_BOX_PATH, "run", "-c", str(temp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    last_message = ""
    try:
        time.sleep(0.7)
        if process.poll() is not None:
            stderr = (process.stderr.read() if process.stderr else "")[-300:]
            return None, f"proxy_skipped: sing-box 启动失败 {stderr.strip()}"
        for url in PROXY_TEST_URLS or ["https://www.gstatic.com/generate_204"]:
            start = time.perf_counter()
            try:
                result = subprocess.run(
                    [
                        "curl",
                        "-x",
                        f"socks5h://127.0.0.1:{port}",
                        "-L",
                        "--connect-timeout",
                        "6",
                        "--max-time",
                        "10",
                        "-sS",
                        "-o",
                        os.devnull,
                        "-w",
                        "%{http_code} %{time_total}",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                elapsed = int((time.perf_counter() - start) * 1000)
                output = (result.stdout or "").strip()
                error = (result.stderr or "").strip()
                code = output.split()[0] if output else ""
                last_message = f"{url} {output} {error}".strip()
                if result.returncode == 0 and code in {"200", "204"}:
                    return elapsed, "proxy_ok"
            except subprocess.TimeoutExpired:
                last_message = f"{url} timeout"
        return None, f"proxy_failed: {last_message[:160]}"
    finally:
        try:
            process.terminate()
            process.wait(timeout=2)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
        temp_path.unlink(missing_ok=True)


def test_node_latency(raw: str, timeout: float = 5.0) -> tuple[int | None, str]:
    target = return_test_target()
    if target:
        host, port = target
        status_label = f"回国目标 {host}:{port} 连通"
    else:
        endpoint = node_endpoint(raw)
        if not endpoint or not endpoint[0]:
            return None, "无法解析地址"
        host, port = endpoint
        status_label = "节点入口连通"
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = int((time.perf_counter() - start) * 1000)
            return elapsed, status_label
    except OSError as exc:
        label = f"{host}:{port}"
        return None, f"回国目标失败：{label} {exc.__class__.__name__}" if target else f"失败：{exc.__class__.__name__}"


def update_node_test_result(node_id: int, latency_ms: int | None, status: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            "UPDATE nodes SET last_latency_ms = ?, last_tested_at = ?, test_status = ? WHERE id = ?",
            (latency_ms, now, status, node_id),
        )
    update_node_entry_check(f"manual:{node_id}", latency_ms, status)


@app.route("/admin/node-assets/<asset_key>/test", methods=["POST"])
@login_required
def speedtest_node_asset(asset_key: str):
    asset = get_node_asset(asset_key)
    if not asset:
        flash("节点资产不存在。")
        return redirect(url_for("nodes_admin"))
    latency_ms, status = test_node_latency(asset["raw"])
    update_node_entry_check(asset_key, latency_ms, status)
    if asset.get("source_type") == "manual":
        update_node_test_result(asset["id"], latency_ms, status)
    audit("节点测速", "node_asset", asset_key, f"{latency_ms} ms" if latency_ms is not None else status)
    flash(f"测速完成：{latency_ms} ms" if latency_ms is not None else f"测速失败：{status}")
    return redirect(url_for("nodes_admin", asset_key=asset_key))


@app.route("/admin/node-assets/<asset_key>/proxy-test", methods=["POST"])
@login_required
def proxytest_node_asset(asset_key: str):
    asset = get_node_asset(asset_key)
    if not asset:
        flash("节点资产不存在。")
        return redirect(url_for("nodes_admin"))
    latency_ms, status = real_proxy_test_node(asset["raw"])
    normalized = "proxy_ok" if latency_ms is not None and status == "proxy_ok" else "proxy_skipped" if str(status).startswith("proxy_skipped") else "proxy_failed"
    update_node_check(asset_key, latency_ms, normalized)
    if asset.get("source_type") == "manual":
        update_node_test_result(asset["id"], latency_ms, "真可用" if normalized == "proxy_ok" else "跳过测试" if normalized == "proxy_skipped" else "真测失败")
    audit("真实代理测试", "node_asset", asset_key, f"{latency_ms} ms" if latency_ms is not None else status)
    flash(f"真实代理测试通过：{latency_ms} ms" if latency_ms is not None else f"真实代理测试未判定：{status}" if normalized == "proxy_skipped" else f"真实代理测试失败：{status}")
    return redirect(url_for("nodes_admin", asset_key=asset_key))


@app.route("/admin/nodes/<int:node_id>/test", methods=["POST"])
@login_required
def speedtest_node(node_id: int):
    return speedtest_node_asset(f"manual:{node_id}")


@app.route("/admin/speedtest", methods=["POST"])
@login_required
def speedtest_all():
    rows = node_view_rows()[:GEO_REFRESH_LIMIT]
    ok = 0
    for row in rows:
        latency_ms, status = test_node_latency(row["raw"])
        update_node_entry_check(row["asset_key"], latency_ms, status)
        if row.get("source_type") == "manual":
            update_node_test_result(row["id"], latency_ms, status)
        if latency_ms is not None:
            ok += 1
    flash(f"测速完成：{ok}/{len(rows)} 个节点连通。")
    return redirect(url_for("nodes_admin"))


@app.route("/admin/proxy-test", methods=["POST"])
@login_required
def proxytest_filtered_nodes():
    filters = {
        "q": request.form.get("q", "").strip(),
        "region": request.form.get("region", "").strip(),
        "status": request.form.get("status", "").strip(),
        "protocol": request.form.get("protocol", "").strip(),
    }
    source = request.form.get("source", "upstream").strip()
    rows = filter_nodes(node_view_rows(), filters)
    if source == "upstream":
        rows = [row for row in rows if row.get("source_type") == "upstream"]
    rows = rows[:max(1, PROXY_TEST_LIMIT)]
    ok = 0
    failed = 0
    unsupported = 0
    skipped = 0
    for row in rows:
        latency_ms, status = real_proxy_test_node(row["raw"])
        normalized = "proxy_ok" if latency_ms is not None and status == "proxy_ok" else "proxy_skipped" if str(status).startswith("proxy_skipped") else "proxy_failed"
        if normalized == "proxy_skipped" and "暂不支持" in status:
            unsupported += 1
        elif normalized == "proxy_ok":
            ok += 1
        elif normalized == "proxy_skipped":
            skipped += 1
        else:
            failed += 1
        update_node_check(row["asset_key"], latency_ms, normalized)
        if row.get("source_type") == "manual":
            update_node_test_result(row["id"], latency_ms, "真可用" if normalized == "proxy_ok" else "跳过测试" if normalized == "proxy_skipped" else "真测失败")
    audit("批量真实代理测试", "node_asset", "filtered", f"ok={ok}, failed={failed}, skipped={skipped}, unsupported={unsupported}, total={len(rows)}")
    flash(f"真实代理测试完成：通过 {ok}，失败 {failed}，跳过 {skipped}，暂不支持 {unsupported}，本次处理 {len(rows)}。")
    return redirect(url_for("nodes_admin", **{key: value for key, value in filters.items() if value}))


SUBSCRIPTION_FORMAT_ALIASES = {
    "clash": "clash",
    "clashmeta": "clash",
    "clash-meta": "clash",
    "mihomo": "clash",
    "yaml": "clash",
    "yml": "clash",
    "hiddify": "v2ray",
    "stash": "clash",
    "surge": "surge",
    "quantumult": "qx",
    "quantumultx": "qx",
    "quantumult-x": "qx",
    "qx": "qx",
    "v2ray": "v2ray",
    "base64": "v2ray",
    "shadowrocket": "v2ray",
    "v2rayn": "v2ray",
    "v2rayng": "v2ray",
    "nekobox": "v2ray",
    "nekoray": "v2ray",
    "loon": "v2ray",
    "egern": "v2ray",
    "streisand": "v2ray",
}


def detect_client(ua: str) -> str:
    ua = (ua or "").lower()
    if any(k in ua for k in ["quantumult", "quantumult%20x"]):
        return "qx"
    if "surge" in ua:
        return "surge"
    # Hiddify 4.x accepts Clash profiles, but its strict clash2singbox
    # conversion can reject otherwise valid Mihomo profiles. URI lists are
    # its native and most interoperable subscription input.
    if "hiddify" in ua:
        return "v2ray"
    # These clients understand Clash Meta profiles and can preserve the
    # server-defined select/url-test/fallback groups.
    clash_clients = [
        "clash", "mihomo", "stash", "surfboard", "flclash",
        "openclash", "clash-verge", "clashx", "clashmi", "cfa", "cmfa",
    ]
    if any(k in ua for k in clash_clients):
        return "clash"
    # URI subscription clients (Shadowrocket, v2rayN/NG, NekoBox, Loon,
    # Egern, Streisand, sing-box frontends, etc.) share the Base64 fallback.
    return "v2ray"


def requested_subscription_format() -> str:
    for key in ("client", "format", "target"):
        requested = request.args.get(key, "").strip().lower().replace("_", "-")
        if requested:
            return SUBSCRIPTION_FORMAT_ALIASES.get(requested, detect_client(request.headers.get("User-Agent", "")))
    return detect_client(request.headers.get("User-Agent", ""))


def normalize_outbound_uri(raw: str) -> str:
    raw = (raw or "").strip()
    if raw.startswith(("hysteria2://", "hy2://")):
        if raw.startswith("hy2://"):
            raw = "hysteria2://" + raw[len("hy2://"):]
        raw = raw.replace("/?", "?", 1)
        try:
            parsed = urlparse(raw)
            allowed = {
                "sni", "peer", "insecure", "allowInsecure", "mport", "ports",
                "obfs", "obfs-password", "obfs_password", "alpn",
            }
            query = []
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                if key in allowed:
                    query.append((key, value))
            rebuilt = parsed._replace(query=urlencode(query, doseq=True, safe="-:,."))
            raw = rebuilt.geturl()
        except Exception:
            pass
    return raw


def to_v2ray_base64(nodes: list[str]) -> str:
    normalized = [normalize_outbound_uri(node) for node in nodes if normalize_outbound_uri(node)]
    return base64.b64encode("\n".join(normalized).encode()).decode()


def parse_clash_node(line: str, display: str = "") -> dict | None:
    if line.startswith(("http://", "https://")):
        proxy = parse_http_to_clash(line)
    elif line.startswith("ss://"):
        proxy = parse_ss_to_clash(line)
    elif line.startswith("vmess://"):
        proxy = parse_vmess_to_clash(line)
    elif line.startswith("vless://"):
        proxy = parse_vless_to_clash(line)
    elif line.startswith("trojan://"):
        proxy = parse_trojan_to_clash(line)
    elif line.startswith(("hysteria2://", "hy2://")):
        proxy = parse_hysteria2_to_clash(line)
    elif line.startswith("hysteria://"):
        proxy = parse_hysteria_to_clash(line)
    elif line.startswith("ssr://"):
        proxy = parse_ssr_to_clash(line)
    else:
        proxy = None
    if proxy and display:
        proxy["name"] = display
    return proxy


def subscription_items_to_nodes(items: list[dict]) -> list[str]:
    return [normalize_outbound_uri(item["raw"]) for item in items]


def to_clash_yaml(nodes: list[str] | list[dict]) -> str:
    proxies = []
    for item in nodes:
        line = item["raw"] if isinstance(item, dict) else item
        display = item.get("name", "") if isinstance(item, dict) else ""
        proxy = None
        if isinstance(item, dict) and item.get("clash_proxy"):
            proxy = normalize_clash_proxy(item.get("clash_proxy"))
            if proxy and display:
                proxy["name"] = display
        if not proxy:
            proxy = parse_clash_node(line, display)
        if proxy:
            proxies.append(proxy)
    seen_names: dict[str, int] = {}
    for proxy in proxies:
        base_name = proxy["name"]
        count = seen_names.get(base_name, 0)
        seen_names[base_name] = count + 1
        if count:
            proxy["name"] = f"{base_name} {count + 1}"
    proxy_names = [p["name"] for p in proxies]
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "节点选择", "type": "select", "proxies": ["自动选择", "故障转移", "DIRECT"] + proxy_names},
            {"name": "自动选择", "type": "url-test", "proxies": list(proxy_names), "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
            {"name": "故障转移", "type": "fallback", "proxies": list(proxy_names), "url": "https://www.gstatic.com/generate_204", "interval": 300},
            {"name": "全球代理", "type": "select", "proxies": ["节点选择", "自动选择", "故障转移"] + proxy_names},
            {"name": "AI 服务", "type": "select", "proxies": ["全球代理", "节点选择", "自动选择"] + proxy_names},
            {"name": "Google", "type": "select", "proxies": ["全球代理", "节点选择", "自动选择"] + proxy_names},
            {"name": "YouTube", "type": "select", "proxies": ["全球代理", "节点选择", "自动选择"] + proxy_names},
            {"name": "Telegram", "type": "select", "proxies": ["全球代理", "节点选择", "自动选择"] + proxy_names},
            {"name": "苹果服务", "type": "select", "proxies": ["DIRECT", "全球代理"]},
            {"name": "国内直连", "type": "select", "proxies": ["DIRECT", "全球代理"]},
        ],
        "rules": [
            "DOMAIN-SUFFIX,openai.com,AI 服务",
            "DOMAIN-SUFFIX,chatgpt.com,AI 服务",
            "DOMAIN-SUFFIX,oaistatic.com,AI 服务",
            "DOMAIN-SUFFIX,oaiusercontent.com,AI 服务",
            "DOMAIN-SUFFIX,anthropic.com,AI 服务",
            "DOMAIN-SUFFIX,claude.ai,AI 服务",
            "DOMAIN-SUFFIX,google.com,Google",
            "DOMAIN-SUFFIX,googleapis.com,Google",
            "DOMAIN-SUFFIX,gstatic.com,Google",
            "DOMAIN-SUFFIX,googlevideo.com,YouTube",
            "DOMAIN-SUFFIX,youtube.com,YouTube",
            "DOMAIN-SUFFIX,ytimg.com,YouTube",
            "DOMAIN-SUFFIX,telegram.org,Telegram",
            "IP-CIDR,91.108.4.0/22,Telegram,no-resolve",
            "IP-CIDR,91.108.8.0/22,Telegram,no-resolve",
            "IP-CIDR,149.154.160.0/20,Telegram,no-resolve",
            "DOMAIN-SUFFIX,apple.com,苹果服务",
            "DOMAIN-SUFFIX,icloud.com,苹果服务",
            "DOMAIN-SUFFIX,mzstatic.com,苹果服务",
            "DOMAIN-SUFFIX,cn,国内直连",
            "GEOIP,CN,国内直连",
            "MATCH,全球代理",
        ],
    }
    return yaml.dump(config, allow_unicode=True, sort_keys=False)


def parse_http_to_clash(line: str) -> dict | None:
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        proxy = {
            "name": unquote(parsed.fragment) or "http-node",
            "type": "http",
            "server": parsed.hostname,
            "port": int(parsed.port or (443 if parsed.scheme == "https" else 80)),
        }
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if username:
            proxy["username"] = username
        if password:
            proxy["password"] = password
        if parsed.scheme == "https" or str((params.get("tls") or [""])[0]).lower() in {"1", "true", "yes"}:
            proxy["tls"] = True
        if str((params.get("allowInsecure") or params.get("insecure") or [""])[0]).lower() in {"1", "true", "yes"}:
            proxy["skip-cert-verify"] = True
        return proxy
    except Exception:
        return None


def parse_ss_to_clash(line: str) -> dict | None:
    try:
        parsed = urlparse(line)
        payload = line[5:]
        if "@" not in payload:
            return parse_ss_to_clash("ss://" + b64decode_text(payload))
        userinfo, _server = payload.split("@", 1)
        method, password = b64decode_text(userinfo).split(":", 1)
        proxy = {"name": unquote(parsed.fragment) or "ss-node", "type": "ss", "server": parsed.hostname, "port": parsed.port, "cipher": method, "password": password}
        params = parse_qs(parsed.query)
        if "plugin" in params:
            plugin = params["plugin"][0]
            parts = plugin.split(";")
            proxy["plugin"] = parts[0]
            opts = {}
            for part in parts[1:]:
                if "=" in part:
                    key, value = part.split("=", 1)
                    opts[key] = True if value == "true" else value
            if opts:
                proxy["plugin-opts"] = opts
        return proxy
    except Exception:
        return None


def parse_vmess_to_clash(line: str) -> dict | None:
    try:
        info = json.loads(b64decode_text(line[8:]))
        proxy = {
            "name": info.get("ps") or info.get("remark") or info.get("name") or "vmess-node",
            "type": "vmess",
            "server": info.get("add", ""),
            "port": int(info.get("port", 443)),
            "uuid": info.get("id", ""),
            "alterId": int(info.get("aid", 0)),
            "cipher": info.get("scy", "auto"),
            "network": info.get("net", "tcp"),
            "tls": info.get("tls", "") == "tls",
        }
        if info.get("sni"):
            proxy["servername"] = info["sni"]
        if info.get("net") == "ws":
            proxy["ws-opts"] = {"path": info.get("path", "/"), "headers": {"Host": info.get("host") or info.get("add", "")}}
        if info.get("net") == "grpc":
            proxy["grpc-opts"] = {"serviceName": info.get("path", "")}
        return proxy
    except Exception:
        return None


def parse_vless_to_clash(line: str) -> dict | None:
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        network = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        proxy = {"name": unquote(parsed.fragment) or "vless-node", "type": "vless", "server": parsed.hostname, "port": parsed.port, "uuid": parsed.username, "network": network, "tls": security != "none"}
        if params.get("sni"):
            proxy["servername"] = params["sni"][0]
        if params.get("fp"):
            proxy["client-fingerprint"] = params["fp"][0]
        if params.get("alpn"):
            proxy["alpn"] = [item for item in params["alpn"][0].split(",") if item]
        if params.get("allowInsecure") or params.get("insecure"):
            proxy["skip-cert-verify"] = str((params.get("allowInsecure") or params.get("insecure") or [""])[0]).lower() in {"1", "true", "yes"}
        if params.get("udp"):
            proxy["udp"] = str(params["udp"][0]).lower() in {"1", "true", "yes"}
        if network == "ws":
            proxy["ws-opts"] = {"path": params.get("path", ["/"])[0], "headers": {"Host": params.get("host", [parsed.hostname])[0]}}
        if network == "grpc":
            proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", params.get("service_name", [""]))[0]}
        if network == "http":
            proxy["http-opts"] = {"path": [params.get("path", ["/"])[0]], "headers": {"Host": [params.get("host", [parsed.hostname])[0]]}}
        if security == "reality":
            proxy["reality-opts"] = {"public-key": params.get("pbk", [""])[0], "short-id": params.get("sid", [""])[0]}
        return proxy
    except Exception:
        return None


def parse_trojan_to_clash(line: str) -> dict | None:
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        proxy = {"name": unquote(parsed.fragment) or "trojan-node", "type": "trojan", "server": parsed.hostname, "port": parsed.port or 443, "password": unquote(parsed.username or "")}
        if params.get("sni"):
            proxy["sni"] = params["sni"][0]
        if params.get("alpn"):
            proxy["alpn"] = [item for item in params["alpn"][0].split(",") if item]
        if params.get("fp"):
            proxy["client-fingerprint"] = params["fp"][0]
        if params.get("allowInsecure") or params.get("insecure"):
            proxy["skip-cert-verify"] = str((params.get("allowInsecure") or params.get("insecure") or [""])[0]).lower() in {"1", "true", "yes"}
        if params.get("udp"):
            proxy["udp"] = str(params["udp"][0]).lower() in {"1", "true", "yes"}
        if params.get("type", ["tcp"])[0] == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {"path": params.get("path", ["/"])[0], "headers": {"Host": params.get("host", [parsed.hostname])[0]}}
        if params.get("type", ["tcp"])[0] == "grpc":
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", params.get("service_name", [""]))[0]}
        return proxy
    except Exception:
        return None


def parse_hysteria2_to_clash(line: str) -> dict | None:
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        proxy = {"name": unquote(parsed.fragment) or "hysteria2-node", "type": "hysteria2", "server": parsed.hostname, "port": parsed.port or 443, "password": unquote(parsed.username or "")}
        if params.get("sni"):
            proxy["sni"] = params["sni"][0]
        if params.get("insecure", ["0"])[0] == "1":
            proxy["skip-cert-verify"] = True
        if params.get("mport"):
            proxy["mport"] = params["mport"][0]
            proxy["ports"] = params["mport"][0]
        if params.get("ports"):
            proxy["ports"] = params["ports"][0]
            proxy["mport"] = params["ports"][0]
        if params.get("obfs"):
            proxy["obfs"] = params["obfs"][0]
        if params.get("obfs-password"):
            proxy["obfs-password"] = params["obfs-password"][0]
        proxy["udp"] = True
        return proxy
    except Exception:
        return None


def parse_hysteria_to_clash(line: str) -> dict | None:
    try:
        parsed = urlparse(line)
        params = parse_qs(parsed.query)
        proxy = {"name": unquote(parsed.fragment) or "hysteria-node", "type": "hysteria", "server": parsed.hostname, "port": parsed.port or 443, "auth_str": params.get("auth", [""])[0], "up": params.get("upmbps", ["100"])[0], "down": params.get("downmbps", ["100"])[0]}
        if params.get("peer"):
            proxy["sni"] = params["peer"][0]
        return proxy
    except Exception:
        return None


def parse_ssr_to_clash(line: str) -> dict | None:
    try:
        decoded = b64decode_text(line[6:])
        parts = decoded.split("/?")
        main = parts[0].split(":")
        params = parse_qs(parts[1]) if len(parts) > 1 else {}
        name = b64decode_text(params["remarks"][0]) if "remarks" in params else "ssr-node"
        proxy = {"name": name, "type": "ssr", "server": main[0], "port": int(main[1]), "protocol": main[2], "cipher": main[3], "obfs": main[4], "password": b64decode_text(main[5])}
        if "obfsparam" in params:
            proxy["obfs-param"] = b64decode_text(params["obfsparam"][0])
        if "protoparam" in params:
            proxy["protocol-param"] = b64decode_text(params["protoparam"][0])
        return proxy
    except Exception:
        return None


def profile_proxy_lines(nodes: list[str], renderer) -> tuple[list[str], list[str]]:
    lines = []
    names = []
    used: dict[str, int] = {}
    for node in nodes:
        line = renderer(node)
        if not line or "=" not in line:
            continue
        raw_name, definition = line.split("=", 1)
        base_name = re.sub(r"[,=\r\n]+", " ", raw_name).strip() or "node"
        count = used.get(base_name, 0) + 1
        used[base_name] = count
        name = base_name if count == 1 else f"{base_name} {count}"
        names.append(name)
        lines.append(f"{name} = {definition.strip()}")
    return lines, names


def to_surge(nodes: list[str]) -> str:
    proxy_lines, names = profile_proxy_lines(nodes, surge_line)
    if not proxy_lines:
        return ""
    candidates = ", ".join(names)
    sections = [
        "[General]",
        "loglevel = notify",
        "internet-test-url = http://www.gstatic.com/generate_204",
        "proxy-test-url = http://www.gstatic.com/generate_204",
        "test-timeout = 5",
        "",
        "[Proxy]",
        *proxy_lines,
        "",
        "[Proxy Group]",
        f"节点选择 = select, 自动选择, 故障转移, DIRECT, {candidates}",
        f"自动选择 = url-test, {candidates}, url=http://www.gstatic.com/generate_204, interval=300, tolerance=50",
        f"故障转移 = fallback, {candidates}, url=http://www.gstatic.com/generate_204, interval=300",
        "全球代理 = select, 节点选择, 自动选择, 故障转移",
        "",
        "[Rule]",
        "DOMAIN-SUFFIX,openai.com,全球代理",
        "DOMAIN-SUFFIX,chatgpt.com,全球代理",
        "DOMAIN-SUFFIX,google.com,全球代理",
        "DOMAIN-SUFFIX,youtube.com,全球代理",
        "DOMAIN-SUFFIX,telegram.org,全球代理",
        "GEOIP,CN,DIRECT",
        "FINAL,全球代理",
    ]
    return "\n".join(sections) + "\n"


def surge_line(line: str) -> str:
    try:
        if line.startswith("ss://"):
            parsed = urlparse(line)
            payload = line[5:]
            if "@" not in payload:
                return surge_line("ss://" + b64decode_text(payload))
            userinfo, server_part = payload.split("@", 1)
            method, password = b64decode_text(userinfo).split(":", 1)
            host, port = server_part.split("#", 1)[0].rsplit(":", 1)
            return f"{unquote(parsed.fragment) or 'ss'} = ss, {host}, {port}, encrypt-method={method}, password={password}"
        if line.startswith("vmess://"):
            info = json.loads(b64decode_text(line[8:]))
            tls = "tls=true, " if info.get("tls") == "tls" else ""
            return f"{info.get('ps', 'vmess')} = vmess, {info.get('add', '')}, {info.get('port', 443)}, username={info.get('id', '')}, {tls}vmess-aead=true"
        if line.startswith("trojan://"):
            parsed = urlparse(line)
            sni = (parse_qs(parsed.query).get("sni") or parse_qs(parsed.query).get("peer") or parse_qs(parsed.query).get("host") or [""])[0]
            tls = f", sni={sni}" if sni else ""
            return f"{unquote(parsed.fragment) or 'trojan'} = trojan, {parsed.hostname}, {parsed.port or 443}, password={parsed.username}{tls}"
    except Exception:
        return ""
    return ""


def to_qx(nodes: list[str]) -> str:
    proxy_lines, names = profile_proxy_lines(nodes, qx_line)
    if not proxy_lines:
        return ""
    candidates = ", ".join(names)
    sections = [
        "[general]",
        "server_check_url=http://www.gstatic.com/generate_204",
        "server_check_timeout=5000",
        "",
        "[server_local]",
        *proxy_lines,
        "",
        "[policy]",
        f"static=节点选择, 自动选择, 故障转移, direct, {candidates}",
        f"url-latency-benchmark=自动选择, {candidates}, check-interval=300, tolerance=50, alive-checking=false",
        f"available=故障转移, {candidates}",
        "static=全球代理, 节点选择, 自动选择, 故障转移",
        "",
        "[filter_local]",
        "host-suffix, openai.com, 全球代理",
        "host-suffix, chatgpt.com, 全球代理",
        "host-suffix, google.com, 全球代理",
        "host-suffix, youtube.com, 全球代理",
        "host-suffix, telegram.org, 全球代理",
        "geoip, cn, direct",
        "final, 全球代理",
    ]
    return "\n".join(sections) + "\n"


def count_renderable_nodes(fmt: str, nodes: list[str]) -> int:
    if fmt == "clash":
        return sum(1 for node in nodes if parse_clash_node(node))
    if fmt == "surge":
        return sum(1 for node in nodes if surge_line(node))
    if fmt == "qx":
        return sum(1 for node in nodes if qx_line(node))
    return len(nodes)


def qx_line(line: str) -> str:
    try:
        if line.startswith("ss://"):
            parsed = urlparse(line)
            payload = line[5:]
            if "@" not in payload:
                return qx_line("ss://" + b64decode_text(payload))
            userinfo, server_part = payload.split("@", 1)
            method, password = b64decode_text(userinfo).split(":", 1)
            host, port = server_part.split("#", 1)[0].rsplit(":", 1)
            name = unquote(parsed.fragment) or "ss"
            return f"{name}=shadowsocks, {host}:{port}, method={method}, password={password}, tag={name}"
        if line.startswith("vmess://"):
            info = json.loads(b64decode_text(line[8:]))
            name = info.get("ps", "vmess")
            tls = ", over-tls=true" if info.get("tls") == "tls" else ""
            return f"{name}=vmess, {info.get('add', '')}:{info.get('port', 443)}, method=chacha20-poly1305, password={info.get('id', '')}, tag={name}{tls}"
        if line.startswith("trojan://"):
            parsed = urlparse(line)
            name = unquote(parsed.fragment) or "trojan"
            sni = (parse_qs(parsed.query).get("sni") or parse_qs(parsed.query).get("peer") or parse_qs(parsed.query).get("host") or [""])[0]
            tls = f", tls-host={sni}" if sni else ""
            return f"{name}=trojan, {parsed.hostname}:{parsed.port or 443}, password={parsed.username}, tag={name}, over-tls=true{tls}"
    except Exception:
        return ""
    return ""


def safe_header(value: str) -> str:
    try:
        value.encode("ascii")
        return value
    except UnicodeEncodeError:
        return "base64:" + base64.b64encode(value.encode("utf-8")).decode("ascii")


def subscription_headers(user: sqlite3.Row | dict | None = None) -> dict:
    if user:
        total = user["total_bytes"] or 999999999999
        used = user["used_bytes"] or 0
        expire = expire_epoch(user["expire_at"])
        title = safe_header(f"{PROFILE_TITLE}-{user['name']}")
    else:
        total = 999999999999
        used = 0
        expire = 253402300799
        title = safe_header(PROFILE_TITLE)
    return {
        "Subscription-Userinfo": f"upload=0; download={used}; total={total}; expire={expire}",
        "Profile-Update-Interval": "6",
        "Profile-Title": title,
    }


def subs_check_format_path(fmt: str) -> str:
    if fmt == "clash":
        return SUBS_CHECK_CLASH_PATH
    if fmt == "v2ray":
        return SUBS_CHECK_V2RAY_PATH
    if fmt == "surge":
        return SUBS_CHECK_SURGE_PATH
    if fmt == "qx":
        return SUBS_CHECK_QX_PATH
    return SUBS_CHECK_V2RAY_PATH


def subs_check_format_url(fmt: str) -> str:
    path = subs_check_format_path(fmt)
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{SUBS_CHECK_BASE_URL}/{path.lstrip('/')}"


def subs_check_content_type(fmt: str) -> str:
    if fmt == "clash":
        return "text/yaml; charset=utf-8"
    return "text/plain; charset=utf-8"


def fetch_subs_check_subscription(fmt: str) -> tuple[str, str]:
    path = subs_check_format_path(fmt)
    if not path:
        raise ValueError(f"subs-check 未配置 {fmt} 输出路径")
    url = subs_check_format_url(fmt)
    text = fetch_url_text(url)
    if not text.strip():
        raise ValueError(f"subs-check {fmt} 输出为空")
    return text, subs_check_content_type(fmt)


def compose_clash_subscription(text: str) -> str:
    """Turn a Clash proxy list into the complete client-facing profile."""
    try:
        data = yaml.safe_load(text) or {}
    except Exception as exc:
        raise ValueError(f"subs-check Clash 输出无法解析: {exc}") from exc
    proxies = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(proxies, list) or not proxies:
        raise ValueError("subs-check Clash 输出没有可用 proxies")
    items = clash_proxies_to_subscription_items(proxies)
    if not items:
        raise ValueError("subs-check Clash 节点无法转换为订阅资产")
    return to_clash_yaml(items)


def render_subs_check_subscription(fmt: str, user: sqlite3.Row | dict | None = None):
    if fmt in {"surge", "qx"} and not subs_check_format_path(fmt):
        clash_text, _ = fetch_subs_check_subscription("clash")
        items = parse_subscription_items_from_text(clash_text)
        nodes = subscription_items_to_nodes(items)
        text = to_surge(nodes) if fmt == "surge" else to_qx(nodes)
        if not text.strip():
            raise ValueError(f"subs-check 优选池没有可用于 {fmt} 的兼容节点")
        content_type = "text/plain; charset=utf-8"
    else:
        text, content_type = fetch_subs_check_subscription(fmt)
    if fmt == "clash":
        text = compose_clash_subscription(text)
    headers = subscription_headers(user)
    headers["X-Subscription-Engine"] = "subs-check"
    headers["X-Subscription-Format"] = fmt
    return Response(text, content_type=content_type, headers=headers)


def render_subscription(fmt: str, user: sqlite3.Row | dict | None = None, force_engine: str = ""):
    compatibility = ""
    if fmt == "clash" and "hiddify" in request.headers.get("User-Agent", "").lower():
        fmt = "v2ray"
        compatibility = "hiddify-v2ray"
    engine = subscription_engine_state(status_timeout=2)
    force_engine = (force_engine or "").strip().lower()
    if force_engine == "subs-check" and engine["subs_check"].get("ok") and engine["subs_check"].get("node_count", 0) > 0:
        forced_count = safe_int(engine["subs_check"].get("node_count"))
        engine = dict(engine)
        engine.update(
            {
                "active": "subs-check",
                "status": "normal" if forced_count >= engine["min_output_nodes"] else "degraded",
                "degraded": forced_count < engine["min_output_nodes"],
                "default_output_count": forced_count,
                "reason_code": "forced_subs_check",
            }
        )
    use_subs = force_engine == "subs-check" or (not force_engine and engine["use_subs_check"])
    if use_subs:
        try:
            response = render_subs_check_subscription(fmt, user)
            response.headers["X-Subscription-Mode"] = "strict" if force_engine == "subs-check" else engine["mode"]
            response.headers["X-Subscription-Decision"] = engine["reason_code"]
            response.headers["X-Subscription-Status"] = engine["status"]
            response.headers["X-Subscription-Node-Count"] = str(engine["default_output_count"])
            if engine["degraded"]:
                response.headers["X-Subscription-Note"] = "preferred_pool_below_target"
            if compatibility:
                response.headers["X-Subscription-Compatibility"] = compatibility
            return record_subscription_access_event(user, fmt, response, force_engine)
        except Exception as exc:
            app.logger.warning("subs-check subscription emergency fallback for %s: %s", fmt, exc)
            engine = dict(engine)
            engine.update(
                {
                    "active": "manual",
                    "status": "emergency",
                    "degraded": True,
                    "reason_code": "subs_check_render_failed",
                    "reason": f"优选输出生成失败，仅下发手动应急池：{str(exc)[:120]}",
                }
            )
    if engine["active"] == "local" and not force_engine:
        items = load_subscription_items()
    else:
        items = load_manual_subscription_items()
    nodes = subscription_items_to_nodes(items)
    if not nodes:
        return jsonify({"error": "no safe nodes", "status": engine["status"], "reason": engine["reason"]}), 503
    if not count_renderable_nodes(fmt, nodes):
        return jsonify({"error": "no compatible nodes", "format": fmt}), 422
    headers = subscription_headers(user)
    headers["X-Subscription-Engine"] = engine["active"]
    headers["X-Subscription-Mode"] = engine["mode"]
    headers["X-Subscription-Decision"] = engine["reason_code"]
    headers["X-Subscription-Status"] = engine["status"]
    headers["X-Subscription-Node-Count"] = str(len(items))
    if engine["degraded"]:
        headers["X-Subscription-Note"] = "manual_emergency_pool" if engine["status"] == "emergency" else "preferred_pool_below_target"
    headers["X-Subscription-Format"] = fmt
    if compatibility:
        headers["X-Subscription-Compatibility"] = compatibility
    if fmt == "clash":
        return record_subscription_access_event(user, fmt, Response(to_clash_yaml(items), content_type="text/yaml; charset=utf-8", headers=headers), force_engine)
    if fmt == "surge":
        return record_subscription_access_event(user, fmt, Response(to_surge(nodes), content_type="text/plain; charset=utf-8", headers=headers), force_engine)
    if fmt == "qx":
        return record_subscription_access_event(user, fmt, Response(to_qx(nodes), content_type="text/plain; charset=utf-8", headers=headers), force_engine)
    return record_subscription_access_event(user, fmt, Response(to_v2ray_base64(nodes), content_type="text/plain; charset=utf-8", headers=headers), force_engine)


def render_detected_subscription(user: sqlite3.Row | dict | None = None, force_engine: str = ""):
    client = requested_subscription_format()
    response = render_subscription(client, user, force_engine=force_engine)
    if isinstance(response, Response):
        response.headers["X-Subscription-Format"] = client
        response.headers.add("Vary", "User-Agent")
    return response


def subscriber_forbidden(row: sqlite3.Row | dict | None = None):
    reason = "用户不存在" if row is None else subscriber_status(row)
    return jsonify({"error": "subscription unavailable", "reason": reason}), 403


def internal_subs_check_allowed() -> bool:
    host = (request.host or "").lower()
    if host in INTERNAL_SUBS_CHECK_HOSTS:
        return True
    token = request.headers.get("X-Update-Token", "") or request.args.get("token", "")
    return bool(UPDATE_TOKEN and secrets.compare_digest(token, UPDATE_TOKEN))


@app.route("/internal/subs-check/source")
def internal_subs_check_source():
    if not internal_subs_check_allowed():
        return jsonify({"error": "forbidden"}), 403
    items = load_subscription_items(enabled_only=True)
    nodes = subscription_items_to_nodes(items)
    return Response("\n".join(nodes) + ("\n" if nodes else ""), content_type="text/plain; charset=utf-8")


@app.route("/")
def index():
    return redirect(url_for("admin"))


def render_dingyue_subscription(fmt: str = "", force_engine: str = ""):
    user = get_dingyue_subscriber()
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    if not fmt:
        return render_detected_subscription(user, force_engine=force_engine)
    return render_subscription(fmt, user, force_engine=force_engine)


@app.route(DINGYUE_PATH)
def dingyue_auto():
    return render_dingyue_subscription()


@app.route(f"{DINGYUE_PATH}/clash")
@app.route(f"{DINGYUE_PATH}/clash-meta")
@app.route(f"{DINGYUE_PATH}/mihomo")
def dingyue_clash():
    return render_dingyue_subscription("clash")


@app.route(f"{DINGYUE_PATH}/v2ray")
@app.route(f"{DINGYUE_PATH}/base64")
@app.route(f"{DINGYUE_PATH}/hiddify")
@app.route(f"{DINGYUE_PATH}/shadowrocket")
@app.route(f"{DINGYUE_PATH}/loon")
def dingyue_v2ray():
    return render_dingyue_subscription("v2ray")


@app.route(f"{DINGYUE_PATH}/surge")
def dingyue_surge():
    return render_dingyue_subscription("surge")


@app.route(f"{DINGYUE_PATH}/qx")
@app.route(f"{DINGYUE_PATH}/quantumultx")
def dingyue_qx():
    return render_dingyue_subscription("qx")


@app.route(f"{DINGYUE_PATH}/best")
def dingyue_best_auto():
    return render_dingyue_subscription(force_engine="subs-check")


@app.route(f"{DINGYUE_PATH}/best/clash")
def dingyue_best_clash():
    return render_dingyue_subscription("clash", force_engine="subs-check")


@app.route(f"{DINGYUE_PATH}/best/v2ray")
def dingyue_best_v2ray():
    return render_dingyue_subscription("v2ray", force_engine="subs-check")


@app.route(f"{DINGYUE_PATH}/best/surge")
def dingyue_best_surge():
    return render_dingyue_subscription("surge", force_engine="subs-check")


@app.route(f"{DINGYUE_PATH}/best/qx")
def dingyue_best_qx():
    return render_dingyue_subscription("qx", force_engine="subs-check")


@app.route("/clash")
def clash():
    if not subscription_allowed():
        return subscription_forbidden()
    return render_subscription("clash")


@app.route("/v2ray")
def v2ray():
    if not subscription_allowed():
        return subscription_forbidden()
    return render_subscription("v2ray")


@app.route("/surge")
def surge():
    if not subscription_allowed():
        return subscription_forbidden()
    return render_subscription("surge")


@app.route("/qx")
def qx():
    if not subscription_allowed():
        return subscription_forbidden()
    return render_subscription("qx")


@app.route("/best")
def best_auto():
    if not subscription_allowed():
        return subscription_forbidden()
    return render_detected_subscription(force_engine="subs-check")


@app.route("/best/clash")
def best_clash():
    if not subscription_allowed():
        return subscription_forbidden()
    return render_subscription("clash", force_engine="subs-check")


@app.route("/best/v2ray")
def best_v2ray():
    if not subscription_allowed():
        return subscription_forbidden()
    return render_subscription("v2ray", force_engine="subs-check")


@app.route("/sub/<token>")
def subscriber_auto(token: str):
    user = get_subscriber_by_token(token)
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    return render_detected_subscription(user)


@app.route("/sub/<token>/clash")
def subscriber_clash(token: str):
    user = get_subscriber_by_token(token)
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    return render_subscription("clash", user)


@app.route("/sub/<token>/v2ray")
@app.route("/sub/<token>/hiddify")
def subscriber_v2ray(token: str):
    user = get_subscriber_by_token(token)
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    return render_subscription("v2ray", user)


@app.route("/sub/<token>/surge")
def subscriber_surge(token: str):
    user = get_subscriber_by_token(token)
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    return render_subscription("surge", user)


@app.route("/sub/<token>/qx")
def subscriber_qx(token: str):
    user = get_subscriber_by_token(token)
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    return render_subscription("qx", user)


@app.route("/sub/<token>/best")
def subscriber_best_auto(token: str):
    user = get_subscriber_by_token(token)
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    return render_detected_subscription(user, force_engine="subs-check")


@app.route("/sub/<token>/best/clash")
def subscriber_best_clash(token: str):
    user = get_subscriber_by_token(token)
    if not user or not subscriber_allowed(user):
        return subscriber_forbidden(user)
    return render_subscription("clash", user, force_engine="subs-check")


@app.route("/update", methods=["POST"])
def update_nodes():
    token = request.headers.get("X-Update-Token", "")
    if UPDATE_TOKEN and not secrets.compare_digest(token, UPDATE_TOKEN):
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json(silent=True)
    if data and "nodes" in data:
        nodes = [str(node).strip() for node in data["nodes"] if str(node).strip()]
        saved = replace_nodes(nodes)
        return jsonify({"status": "ok", "count": saved, "submitted": len(nodes)})
    text = request.get_data(as_text=True)
    if text:
        nodes = clean_lines(text)
        saved = replace_nodes(nodes)
        return jsonify({"status": "ok", "count": saved, "submitted": len(nodes)})
    return jsonify({"error": "no data"}), 400


@app.route("/api/traffic/report", methods=["POST"])
def traffic_report():
    token = request.headers.get("X-Update-Token", "") or request.args.get("token", "")
    if UPDATE_TOKEN and not secrets.compare_digest(token, UPDATE_TOKEN):
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    users = data.get("users")
    if users is None:
        users = [data]
    updated = 0
    missing = []
    totals = {"upload": 0, "download": 0, "connections": 0, "anomalies": 0, "blocked": 0}
    for item in users:
        traffic_key = str(item.get("traffic_key") or item.get("email") or item.get("user") or "").strip()
        used_bytes = item.get("used_bytes")
        delta_bytes = item.get("delta_bytes")
        is_delta = str(item.get("mode") or "").lower() == "delta" or item.get("is_delta") is True
        if delta_bytes is None and is_delta and ("upload" in item or "download" in item):
            delta_bytes = int(item.get("upload") or 0) + int(item.get("download") or 0)
        if used_bytes is None and delta_bytes is None and "upload" in item and "download" in item:
            used_bytes = int(item.get("upload") or 0) + int(item.get("download") or 0)
        ok = report_subscriber_usage(
            traffic_key,
            used_bytes=int(used_bytes) if used_bytes is not None else None,
            delta_bytes=int(delta_bytes) if delta_bytes is not None else None,
        )
        user_name = ""
        if traffic_key:
            with db() as conn:
                row = conn.execute("SELECT name FROM subscribers WHERE traffic_key = ?", (traffic_key,)).fetchone()
                user_name = row["name"] if row else ""
        event_totals = record_traffic_event(item, traffic_key, user_name)
        totals["upload"] += event_totals["upload"]
        totals["download"] += event_totals["download"]
        totals["connections"] += event_totals["connections"]
        totals["anomalies"] += event_totals["anomaly"]
        totals["blocked"] += event_totals["blocked"]
        if ok:
            updated += 1
        else:
            missing.append(traffic_key or "(empty)")
    record_traffic_snapshot(totals["upload"], totals["download"], totals["connections"], totals["anomalies"], totals["blocked"])
    return jsonify({"status": "ok", "updated": updated, "missing": missing})


@app.route("/api/node-monitor/report", methods=["POST"])
def node_monitor_report():
    token = request.headers.get("X-Update-Token", "") or request.args.get("token", "")
    if UPDATE_TOKEN and not secrets.compare_digest(token, UPDATE_TOKEN):
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    try:
        row = record_node_monitor(data)
    except ValueError as exc:
        return jsonify({"error": "invalid payload", "message": str(exc)}), 400
    asset = get_node_asset(row["asset_key"])
    return jsonify(
        {
            "status": "ok",
            "asset_key": row["asset_key"],
            "reported_at": row["reported_at"],
            "status_label": asset.get("status_label") if asset else "",
            "monitor_fresh": bool(asset.get("monitor_fresh")) if asset else False,
        }
    )


@app.route("/status")
def status():
    rows = list_node_rows()
    subscribers = list_subscribers()
    upstreams = list_upstreams()
    checks = system_checks()
    monitoring = node_monitoring_status()
    engine = subscription_engine_state()
    default_output_count = safe_int(engine.get("default_output_count"))
    asset_pool_count = safe_int(engine.get("asset_pool_count"))
    local_pool_count = safe_int(engine.get("local_count"))
    return jsonify(
        {
            "app_version": APP_VERSION,
            "nodes": len([row for row in rows if row["enabled"]]),
            "total": len(rows),
            "output_nodes": default_output_count,
            "default_output_nodes": default_output_count,
            "default_output_label": engine["default_output_label"],
            "asset_pool_nodes": asset_pool_count,
            "local_pool_nodes": local_pool_count,
            "upstreams": len(upstreams),
            "enabled_upstreams": len([row for row in upstreams if row["enabled"]]),
            "upstream_nodes": len(load_upstream_nodes(enabled_only=True)),
            "subscribers": len(subscribers),
            "active_subscribers": len([user for user in subscribers if user["status"] == "正常"]),
            "database": str(DB_FILE),
            "nodes_file": str(NODES_FILE),
            "public_base_url": public_base_url(),
            "container_port": 8001,
            "subscription_token_enabled": bool(SUB_TOKEN),
            "public_subscription_enabled": checks["public_subscription"]["enabled"],
            "default_password_risk": checks["default_password"],
            "backup_dir_writable": checks["backup"]["writable"],
            "backup_drill_status": checks["backup"]["drill"]["status"],
            "backup_drill_checked": checks["backup"]["drill"]["checked_at"],
            "node_monitoring_enabled": monitoring["enabled"],
            "last_node_monitor_report": monitoring["last_report_label"],
            "subscription_engine": engine["active"],
            "subscription_engine_mode": engine["mode"],
            "subscription_engine_reason": engine["reason"],
            "subscription_engine_use_subs_check": engine["use_subs_check"],
            "subs_check": engine["subs_check"],
            "checks_passed": checks["passed"],
            "checks_total": checks["total"],
            "return_test_target": return_test_target_label(),
            "admin": "/admin",
        }
    )


@app.route("/health")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1").fetchone()
    except sqlite3.Error as exc:
        return jsonify({"status": "error", "database": str(exc)}), 500
    engine = subscription_engine_state(status_timeout=1)
    return jsonify(
        {
            "status": "ok",
            "nodes": len(load_nodes()),
            "output_nodes": engine["default_output_count"],
            "output_label": engine["default_output_label"],
            "version": APP_VERSION,
            "subscription_engine": engine["active"],
            "subscription_engine_mode": engine["mode"],
        }
    )


init_db()
migrate_nodes_file()
ensure_dingyue_subscriber()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "18002")), debug=False)


