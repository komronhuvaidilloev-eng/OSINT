"""
Blackbox OSINT Backend — safe/public-data foundation.

Design goals
------------
* Persistent search history in SQLite.
* Saved result snapshots so old investigations can be reopened.
* Async HTTP with connection pooling, timeouts, retries and concurrency limits.
* Per-source status: SUCCESS / FAILED / TIMEOUT / BLOCKED / UNKNOWN / NOT_CONFIGURED.
* In-memory TTL cache + request de-duplication. History is independent from cache.
* Secret redaction in logs.
* Universal search auto-detection for PHONE / EMAIL / USERNAME / IP / DOMAIN / URL / CRYPTO.
* Public-data oriented pipelines only.
* No fake data: unavailable sources stay unavailable.
* No password storage; password strength endpoint only evaluates the submitted value in RAM.
* No private-person enrichment, credential collection or bypass of access controls.

Run
---
    pip install -r requirements.txt
    uvicorn backend_main:app --host 127.0.0.1 --port 8000

Environment
-----------
Optional:
    DATABASE_PATH=history.db
    HTTP_PROXY=
    USER_AGENT=BlackboxOSINT/4.0
    LOG_LIMIT=500
    CACHE_TTL_SECONDS=300
    HTTP_TIMEOUT_SECONDS=12
    MAX_CONCURRENCY=15

Optional API keys:
    HIBP_API_KEY=
    NUMVERIFY_API_KEY=
    GOOGLE_SAFE_BROWSING_API_KEY=

Important
---------
Only configure APIs you are legally allowed to use.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import html as html_lib
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import sqlite3
import string
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from threading import Lock
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

import aiohttp
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import UploadFile, File as FastFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field


# ============================================================================
# CONFIGURATION
# ============================================================================

APP_NAME = "Blackbox OSINT API"
APP_VERSION = "4.0.0"

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "history.db")))

USER_AGENT = os.getenv("USER_AGENT", "BlackboxOSINT/4.0")
HTTP_PROXY = os.getenv("HTTP_PROXY", "").strip() or None

LOG_LIMIT = max(100, int(os.getenv("LOG_LIMIT", "500")))
CACHE_TTL_SECONDS = max(5, int(os.getenv("CACHE_TTL_SECONDS", "300")))
HTTP_TIMEOUT_SECONDS = max(2, int(os.getenv("HTTP_TIMEOUT_SECONDS", "12")))
MAX_CONCURRENCY = max(1, int(os.getenv("MAX_CONCURRENCY", "15")))
MAX_RESULTS_PER_SOURCE = 100
MAX_BODY_BYTES = 2_000_000
MAX_HISTORY_PAGE_SIZE = 100

STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_BLOCKED = "BLOCKED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_NO_DATA = "NO_DATA"

ALLOWED_TARGET_TYPES = {
    "phone",
    "email",
    "username",
    "ip",
    "domain",
    "url",
    "crypto",
    "password",
}

SAFE_USERNAME_SITES = [
    ("GitHub", "https://github.com/{username}"),
    ("GitLab", "https://gitlab.com/{username}"),
    ("Reddit", "https://www.reddit.com/user/{username}"),
    ("Mastodon", "https://mastodon.social/@{username}"),
    ("Keybase", "https://keybase.io/{username}"),
    ("Dev.to", "https://dev.to/{username}"),
    ("Hacker News", "https://news.ycombinator.com/user?id={username}"),
    ("Twitch", "https://www.twitch.tv/{username}"),
    ("YouTube", "https://www.youtube.com/@{username}"),
    ("Pinterest", "https://www.pinterest.com/{username}/"),
]


# ============================================================================
# MODELS
# ============================================================================

class GlobalSearchRequest(BaseModel):
    query: str
    type: Optional[str] = None


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    user_id: str = Field(default="local", min_length=1, max_length=128)


class HistoryRecord(BaseModel):
    search_id: str
    user_id: str
    search_type: str
    original_query: str
    normalized_query: str
    timestamp: str
    duration_ms: float
    status: str
    source_count: int
    success_count: int
    error_count: int
    result_count: int


class HistoryDeleteRequest(BaseModel):
    search_ids: List[str] = Field(min_length=1, max_length=100)


class ExportRequest(BaseModel):
    search_id: str
    format: str = Field(pattern="^(json|csv|txt|html)$")


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class SourceCheckRequest(BaseModel):
    source: str = Field(min_length=1, max_length=128)


class PortRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)


class PingRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)


class SSLRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=255)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class SourceResult:
    source: str
    category: str
    status: str
    duration_ms: float
    retrieved_at: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    url: Optional[str] = None
    confidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SearchContext:
    search_id: str
    query: str
    normalized_query: str
    target_type: str
    started_at: str
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    sources: List[SourceResult] = field(default_factory=list)

    def log(self, stage: str, message: str) -> None:
        self.timeline.append(
            {
                "timestamp": now_iso(),
                "stage": stage,
                "message": message,
            }
        )
        self.logs.append(
            {
                "timestamp": now_iso(),
                "stage": stage,
                "message": redact_secrets(message),
            }
        )


@dataclass
class CacheEntry:
    expires_at: float
    value: Any


@dataclass
class SourceDefinition:
    name: str
    category: str
    timeout: float
    requires_api_key: Optional[str]
    enabled: bool = True
    health_url: Optional[str] = None


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def now_iso() -> str:
    return datetime.now(dt_timezone.utc).isoformat()


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def clamp_text(value: Any, limit: int = 1000) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def redact_secrets(text: str) -> str:
    """Redact common secret-bearing values before anything enters logs."""
    patterns = [
        (r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+", r"\1[REDACTED]"),
        (r"(?i)(api[_-]?key\s*[=:]\s*)[^\s&]+", r"\1[REDACTED]"),
        (r"(?i)(access[_-]?token\s*[=:]\s*)[^\s&]+", r"\1[REDACTED]"),
        (r"(?i)(bot[_-]?token\s*[=:]\s*)[^\s&]+", r"\1[REDACTED]"),
        (r"(?i)(password\s*[=:]\s*)[^\s&]+", r"\1[REDACTED]"),
        (r"(?i)(cookie\s*[=:]\s*)[^\s]+", r"\1[REDACTED]"),
    ]
    result = text
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result)
    return result


def normalize_query(query: str, target_type: Optional[str] = None) -> str:
    value = query.strip()
    if target_type == "email":
        return value.lower()
    if target_type == "domain":
        value = value.lower()
        value = re.sub(r"^https?://", "", value)
        return value.rstrip("/")
    if target_type == "url":
        return value
    if target_type == "username":
        return value.lstrip("@").strip()
    if target_type == "phone":
        return re.sub(r"[^\d+]", "", value)
    return value.strip()


def is_valid_domain(value: str) -> bool:
    if len(value) > 253:
        return False
    value = value.rstrip(".")
    labels = value.split(".")
    if len(labels) < 2:
        return False
    pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return all(pattern.match(label) for label in labels)


def is_valid_email(value: str) -> bool:
    if len(value) > 320:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", value))


def detect_target_type(text: str) -> str:
    """Detect universal-search input in a deterministic order."""
    value = text.strip()

    if is_valid_email(value):
        return "email"

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if re.match(r"^https?://", value, re.IGNORECASE):
        return "url"

    digits = re.sub(r"\D", "", value)
    if 10 <= len(digits) <= 15:
        if value.startswith(("+", "00", "7", "8", "(")) or " " in value:
            return "phone"

    if is_valid_domain(value):
        return "domain"

    if value.lower().startswith(("bc1", "1", "3", "0x")) and 20 <= len(value) <= 90:
        return "crypto"

    return "username"


def extract_domain(value: str) -> str:
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    return value.split("/")[0].split(":")[0]


def iso_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=dt_timezone.utc).isoformat()


def hash_key(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"


# ============================================================================
# PERSISTENT DATABASE
# ============================================================================

class Database:
    """Small SQLite layer. History survives process restarts."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _initialize(self) -> None:
        with self.lock:
            conn = self.connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS schema_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS searches (
                        search_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        search_type TEXT NOT NULL,
                        original_query TEXT NOT NULL,
                        normalized_query TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        duration_ms REAL NOT NULL DEFAULT 0,
                        status TEXT NOT NULL,
                        source_count INTEGER NOT NULL DEFAULT 0,
                        success_count INTEGER NOT NULL DEFAULT 0,
                        error_count INTEGER NOT NULL DEFAULT 0,
                        result_count INTEGER NOT NULL DEFAULT 0,
                        snapshot_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_searches_user_time
                    ON searches(user_id, timestamp DESC);

                    CREATE INDEX IF NOT EXISTS idx_searches_type_time
                    ON searches(search_type, timestamp DESC);

                    CREATE TABLE IF NOT EXISTS source_health (
                        source TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        latency_ms REAL,
                        last_check TEXT,
                        success_count INTEGER NOT NULL DEFAULT 0,
                        fail_count INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT
                    );
                    """
                )

                conn.execute(
                    """
                    INSERT INTO schema_meta(key, value)
                    VALUES('version', '4')
                    ON CONFLICT(key) DO UPDATE SET value='4'
                    """
                )

                conn.commit()
            finally:
                conn.close()

    def save_search(
        self,
        search_id: str,
        user_id: str,
        search_type: str,
        original_query: str,
        normalized_query: str,
        duration_ms: float,
        status: str,
        source_count: int,
        success_count: int,
        error_count: int,
        result_count: int,
        snapshot: Dict[str, Any],
    ) -> None:
        with self.lock:
            conn = self.connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO searches(
                        search_id,
                        user_id,
                        search_type,
                        original_query,
                        normalized_query,
                        timestamp,
                        duration_ms,
                        status,
                        source_count,
                        success_count,
                        error_count,
                        result_count,
                        snapshot_json,
                        created_at
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        search_id,
                        user_id,
                        search_type,
                        original_query,
                        normalized_query,
                        now_iso(),
                        duration_ms,
                        status,
                        source_count,
                        success_count,
                        error_count,
                        result_count,
                        json.dumps(snapshot, ensure_ascii=False),
                        now_iso(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_search(self, search_id: str) -> Optional[Dict[str, Any]]:
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM searches WHERE search_id = ?",
                (search_id,),
            ).fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["snapshot"] = json.loads(item.pop("snapshot_json"))
            except json.JSONDecodeError:
                item["snapshot"] = {}
            return item
        finally:
            conn.close()

    def list_searches(
        self,
        user_id: str,
        offset: int = 0,
        limit: int = 50,
        search_type: Optional[str] = None,
        query_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        limit = min(max(limit, 1), MAX_HISTORY_PAGE_SIZE)
        offset = max(offset, 0)

        sql = "SELECT * FROM searches WHERE user_id = ?"
        params: List[Any] = [user_id]

        if search_type:
            sql += " AND search_type = ?"
            params.append(search_type)

        if query_filter:
            sql += " AND (original_query LIKE ? OR normalized_query LIKE ?)"
            pattern = f"%{query_filter}%"
            params.extend([pattern, pattern])

        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        conn = self.connect()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def count_searches(self, user_id: str) -> int:
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM searches WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            return int(row["c"])
        finally:
            conn.close()

    def delete_searches(self, user_id: str, search_ids: Iterable[str]) -> int:
        ids = list(search_ids)
        if not ids:
            return 0

        placeholders = ",".join("?" for _ in ids)

        with self.lock:
            conn = self.connect()
            try:
                params: List[Any] = [user_id, *ids]
                cur = conn.execute(
                    f"""
                    DELETE FROM searches
                    WHERE user_id = ? AND search_id IN ({placeholders})
                    """,
                    params,
                )
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    def clear_history(self, user_id: str) -> int:
        with self.lock:
            conn = self.connect()
            try:
                cur = conn.execute(
                    "DELETE FROM searches WHERE user_id = ?",
                    (user_id,),
                )
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    def update_source_health(
        self,
        source: str,
        status: str,
        latency_ms: float,
        error: Optional[str] = None,
    ) -> None:
        with self.lock:
            conn = self.connect()
            try:
                conn.execute(
                    """
                    INSERT INTO source_health(
                        source, status, latency_ms, last_check,
                        success_count, fail_count, last_error
                    )
                    VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(source) DO UPDATE SET
                        status=excluded.status,
                        latency_ms=excluded.latency_ms,
                        last_check=excluded.last_check,
                        success_count=source_health.success_count
                            + CASE WHEN excluded.status='SUCCESS' THEN 1 ELSE 0 END,
                        fail_count=source_health.fail_count
                            + CASE WHEN excluded.status='SUCCESS' THEN 0 ELSE 1 END,
                        last_error=excluded.last_error
                    """,
                    (
                        source,
                        status,
                        latency_ms,
                        now_iso(),
                        1 if status == STATUS_SUCCESS else 0,
                        0 if status == STATUS_SUCCESS else 1,
                        error,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_source_health(self) -> List[Dict[str, Any]]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM source_health ORDER BY source"
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


db = Database(DATABASE_PATH)


# ============================================================================
# CACHE AND REQUEST DEDUPLICATION
# ============================================================================

class TTLCache:
    def __init__(self, ttl_seconds: int) -> None:
        self.ttl = ttl_seconds
        self._values: Dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any:
        async with self._lock:
            item = self._values.get(key)
            if not item:
                return None
            if time.monotonic() >= item.expires_at:
                self._values.pop(key, None)
                return None
            return item.value

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            self._values[key] = CacheEntry(
                expires_at=time.monotonic() + self.ttl,
                value=value,
            )

    async def clear(self) -> None:
        async with self._lock:
            self._values.clear()

    async def size(self) -> int:
        async with self._lock:
            return len(self._values)


class RequestDeduplicator:
    def __init__(self) -> None:
        self._inflight: Dict[str, asyncio.Task[Any]] = {}
        self._lock = asyncio.Lock()

    async def run(
        self,
        key: str,
        factory: Callable[[], Awaitable[Any]],
    ) -> Any:
        async with self._lock:
            current = self._inflight.get(key)
            if current is not None:
                return await current

            task = asyncio.create_task(factory())
            self._inflight[key] = task

        try:
            return await task
        finally:
            async with self._lock:
                self._inflight.pop(key, None)


cache = TTLCache(CACHE_TTL_SECONDS)
deduper = RequestDeduplicator()


# ============================================================================
# RUNTIME LOGS
# ============================================================================

runtime_logs: List[Dict[str, Any]] = []
GLOBAL_TASKS: Dict[str, Dict[str, Any]] = {}
GLOBAL_TASK_LOCK = asyncio.Lock()
runtime_log_lock = Lock()


def add_runtime_log(stage: str, message: str) -> None:
    record = {
        "timestamp": now_iso(),
        "stage": stage,
        "message": redact_secrets(clamp_text(message, 2000)),
    }
    with runtime_log_lock:
        runtime_logs.append(record)
        if len(runtime_logs) > LOG_LIMIT:
            del runtime_logs[0 : len(runtime_logs) - LOG_LIMIT]


def get_runtime_logs(limit: int = 200) -> List[Dict[str, Any]]:
    limit = min(max(limit, 1), LOG_LIMIT)
    with runtime_log_lock:
        return runtime_logs[-limit:]


def clear_runtime_logs() -> None:
    with runtime_log_lock:
        runtime_logs.clear()


# ============================================================================
# SOURCE REGISTRY
# ============================================================================

SOURCE_REGISTRY: Dict[str, SourceDefinition] = {
    "ipwho.is": SourceDefinition(
        name="ipwho.is",
        category="IP",
        timeout=8,
        requires_api_key=None,
        health_url="https://ipwho.is/1.1.1.1",
    ),
    "cloudflare-dns": SourceDefinition(
        name="cloudflare-dns",
        category="DNS",
        timeout=8,
        requires_api_key=None,
        health_url="https://1.1.1.1/dns-query",
    ),
    "google-dns": SourceDefinition(
        name="google-dns",
        category="DNS",
        timeout=8,
        requires_api_key=None,
        health_url="https://dns.google/resolve?name=example.com&type=A",
    ),
    "crt.sh": SourceDefinition(
        name="crt.sh",
        category="CERTIFICATE",
        timeout=15,
        requires_api_key=None,
        health_url="https://crt.sh/",
    ),
    "http": SourceDefinition(
        name="http",
        category="HTTP",
        timeout=12,
        requires_api_key=None,
        health_url="https://example.com/",
    ),
    "hibp": SourceDefinition(
        name="hibp",
        category="EMAIL_SECURITY",
        timeout=12,
        requires_api_key="HIBP_API_KEY",
        health_url="https://haveibeenpwned.com/",
    ),
}


# ============================================================================
# ASYNC HTTP CLIENT
# ============================================================================

class HTTPClient:
    def __init__(self) -> None:
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

    async def start(self) -> None:
        if self.session is not None:
            return

        timeout = aiohttp.ClientTimeout(
            total=HTTP_TIMEOUT_SECONDS,
            connect=min(HTTP_TIMEOUT_SECONDS, 5),
            sock_read=HTTP_TIMEOUT_SECONDS,
        )

        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENCY * 2,
            limit_per_host=max(2, MAX_CONCURRENCY // 2),
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
            },
        )

    async def close(self) -> None:
        if self.session is not None:
            await self.session.close()
            self.session = None

    async def request(
        self,
        method: str,
        url: str,
        *,
        timeout: Optional[float] = None,
        retries: int = 2,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Tuple[int, Dict[str, str], bytes, float, str]:
        if self.session is None:
            raise RuntimeError("HTTP client is not started")

        timeout_obj = aiohttp.ClientTimeout(
            total=timeout or HTTP_TIMEOUT_SECONDS,
            connect=min(timeout or HTTP_TIMEOUT_SECONDS, 5),
        )

        last_error = "unknown error"

        for attempt in range(retries + 1):
            started = time.perf_counter()

            try:
                async with self.semaphore:
                    async with self.session.request(
                        method,
                        url,
                        timeout=timeout_obj,
                        proxy=HTTP_PROXY,
                        headers=headers,
                        allow_redirects=True,
                        **kwargs,
                    ) as response:
                        chunks: List[bytes] = []
                        received = 0

                        async for chunk in response.content.iter_chunked(64 * 1024):
                            received += len(chunk)
                            if received > MAX_BODY_BYTES:
                                break
                            chunks.append(chunk)

                        body = b"".join(chunks)
                        duration_ms = (time.perf_counter() - started) * 1000

                        return (
                            response.status,
                            dict(response.headers),
                            body,
                            duration_ms,
                            str(response.url),
                        )

            except asyncio.TimeoutError:
                last_error = "timeout"
                if attempt < retries:
                    await asyncio.sleep(0.25 * (attempt + 1))
                    continue
                raise

            except aiohttp.ClientError as exc:
                last_error = clamp_text(exc)
                if attempt < retries:
                    await asyncio.sleep(0.25 * (attempt + 1))
                    continue
                raise

        raise RuntimeError(last_error)


http_client = HTTPClient()


# ============================================================================
# SOURCE HELPERS
# ============================================================================

def decode_json(body: bytes) -> Dict[str, Any]:
    return json.loads(body.decode("utf-8", errors="replace"))


def classify_http_failure(status: int) -> str:
    if status in {401, 403, 429}:
        return STATUS_BLOCKED
    if 400 <= status < 600:
        return STATUS_FAILED
    return STATUS_UNKNOWN


async def run_source(
    ctx: SearchContext,
    source_name: str,
    operation: Callable[[], Awaitable[Dict[str, Any]]],
) -> SourceResult:
    source_def = SOURCE_REGISTRY.get(source_name)
    category = source_def.category if source_def else "UNKNOWN"
    started = time.perf_counter()

    ctx.log("SOURCE", f"{source_name} started")
    add_runtime_log("SOURCE", f"{source_name} started")

    if source_def and source_def.requires_api_key:
        if not os.getenv(source_def.requires_api_key):
            result = SourceResult(
                source=source_name,
                category=category,
                status=STATUS_NOT_CONFIGURED,
                duration_ms=0,
                retrieved_at=now_iso(),
                error="API NOT CONFIGURED",
            )
            ctx.sources.append(result)
            ctx.log("SOURCE", f"{source_name}: API NOT CONFIGURED")
            return result

    cache_key = hash_key(source_name, ctx.normalized_query)

    cached = await cache.get(cache_key)
    if cached is not None:
        duration_ms = (time.perf_counter() - started) * 1000
        result = SourceResult(
            **cached,
            duration_ms=duration_ms,
            retrieved_at=now_iso(),
        )
        ctx.sources.append(result)
        ctx.log("CACHE", f"{source_name} cache hit")
        return result

    try:
        data = await deduper.run(cache_key, operation)

        status = STATUS_SUCCESS if data else STATUS_NO_DATA
        duration_ms = (time.perf_counter() - started) * 1000

        result = SourceResult(
            source=source_name,
            category=category,
            status=status,
            duration_ms=duration_ms,
            retrieved_at=now_iso(),
            data=data or {},
        )

        cache_payload = result.to_dict()
        await cache.set(cache_key, cache_payload)

        db.update_source_health(source_name, status, duration_ms)
        ctx.sources.append(result)
        ctx.log("SOURCE", f"{source_name} completed: {status}")
        add_runtime_log("SOURCE", f"{source_name} completed: {status}")
        return result

    except asyncio.TimeoutError:
        duration_ms = (time.perf_counter() - started) * 1000
        result = SourceResult(
            source=source_name,
            category=category,
            status=STATUS_TIMEOUT,
            duration_ms=duration_ms,
            retrieved_at=now_iso(),
            error="TIMEOUT",
        )
        db.update_source_health(source_name, result.status, duration_ms, result.error)
        ctx.sources.append(result)
        ctx.log("SOURCE", f"{source_name} timeout")
        add_runtime_log("SOURCE", f"{source_name} timeout")
        return result

    except Exception as exc:
        duration_ms = (time.perf_counter() - started) * 1000
        error_text = clamp_text(exc)
        result = SourceResult(
            source=source_name,
            category=category,
            status=STATUS_FAILED,
            duration_ms=duration_ms,
            retrieved_at=now_iso(),
            error=error_text,
        )
        db.update_source_health(source_name, result.status, duration_ms, error_text)
        ctx.sources.append(result)
        ctx.log("SOURCE", f"{source_name} failed: {error_text}")
        add_runtime_log("SOURCE", f"{source_name} failed")
        return result


# ============================================================================
# PHONE PIPELINE
# ============================================================================

def normalize_phone_local(value: str) -> str:
    value = normalize_query(value, "phone")

    if value.startswith("00"):
        value = "+" + value[2:]

    return value


def format_phone_fallback(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits.startswith("7"):
        return f"+7 {digits[1:4]} {digits[4:7]}-{digits[7:9]}-{digits[9:11]}"
    if len(digits) == 10 and digits.startswith("9"):
        return f"+7 {digits[:3]} {digits[3:6]}-{digits[6:8]}-{digits[8:10]}"
    return value


def _extract_kody_label(html: str, labels: List[str]) -> Optional[str]:
    """Extract labelled value from kody.su HTML — strict, без мусора."""
    plain = re.sub(r"<script\b[^>]*>.*?</script>", " ", html,
                   flags=re.I | re.S)
    plain = re.sub(r"<style\b[^>]*>.*?</style>", " ", plain,
                   flags=re.I | re.S)
    plain = re.sub(r"<[^>]+>", " ", plain)
    plain = re.sub(r"\s+", " ", html_lib.unescape(plain)).strip()

    for label in labels:
        m = re.search(
            rf"{re.escape(label)}\s*[:\-]\s*([^|;]+?)"
            rf"(?=\s*(?:Страна|Регион|Город|Оператор|Время|Модель|"
            rf"Код|База|Проверить)|$)",
            plain,
            re.I,
        )
        if not m:
            continue
        value = m.group(1).strip(" :-|;.,")
        if not value:
            continue
        if len(value) < 2:
            continue
        bad_words = [
            "Загрузка", "Определить", "Популярное", "номеру",
            "телефонному", "справочник", "База", "Код страны",
        ]
        if any(b in value for b in bad_words):
            continue
        if value.lower() in {"и", "а", "или", "нет", "да", "не"}:
            continue
        return value
    return None


async def _fetch_kody_su(phone: str) -> Dict[str, Any]:
    digits = re.sub(r"\D", "", phone)
    if not digits:
        return {"status": STATUS_NO_DATA, "data": {}}

    url = f"https://www.kody.su/check-tel/?number={digits}"
    timeout = aiohttp.ClientTimeout(total=15)

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0 NEXUS-OSINT"},
    ) as session:
        async with session.get(url, allow_redirects=True) as response:
            if response.status == 429:
                return {"status": STATUS_BLOCKED, "error": "RATE LIMITED"}
            if response.status in (401, 403):
                return {"status": STATUS_BLOCKED, "error": f"HTTP {response.status}"}
            if response.status != 200:
                return {"status": STATUS_FAILED, "error": f"HTTP {response.status}"}

            html = await response.text(errors="replace")
            plain = html_lib.unescape(re.sub(r"<[^>]+>", " ", html))
            plain = re.sub(r"\s+", " ", plain)

            data: Dict[str, Any] = {}
            country = _extract_kody_label(html, ["Страна"])
            city = _extract_kody_label(html, ["Город"])
            operator = _extract_kody_label(html, ["Оператор", "Сотовый оператор"])
            region = _extract_kody_label(html, ["Регион"])
            sim_model = _extract_kody_label(html, ["Модель SIM-карты", "Модель SIM карты", "SIM-модель"])
            local_time = _extract_kody_label(html, ["Время региона", "Местное время"])
            operator_region = re.search(
                r"([A-Za-zА-Яа-яЁё0-9_-]+(?:\s+[A-Za-zА-Яа-яЁё0-9_-]+)?)\s*\[([^\]]+)\]",
                plain,
            )
            if operator_region:
                if not operator:
                    operator = operator_region.group(1).strip()
                if not region:
                    region = operator_region.group(2).strip()

            if country:
                data["kody_su_country"] = country
            if region:
                data["kody_su_region"] = region
            if city:
                data["kody_su_city"] = city
            if operator:
                operator = re.sub(r"\s*\[[^\]]+\]", "", operator).strip()
                if operator:
                    data["kody_su_operator"] = operator
            if sim_model:
                data["kody_su_sim_model"] = sim_model
            if local_time:
                data["kody_su_local_time"] = local_time

            data["kody_su_source_url"] = str(response.url)

            return {
                "status": STATUS_SUCCESS if data else STATUS_NO_DATA,
                "data": data,
            }


async def phone_kody_source(ctx: SearchContext) -> Dict[str, Any]:
    result = await _fetch_kody_su(ctx.normalized_query)
    if result.get("status") != STATUS_SUCCESS:
        if result.get("error"):
            raise RuntimeError(result["error"])
        return {}
    return result.get("data", {})


async def phone_numverify_source(ctx: SearchContext) -> Dict[str, Any]:
    api_key = os.getenv("NUMVERIFY_API_KEY")
    if not api_key:
        raise RuntimeError("API NOT CONFIGURED")

    digits = re.sub(r"\D", "", ctx.normalized_query)
    url = (
        "https://apilayer.net/api/validate"
        f"?access_key={quote(api_key)}&number={quote(digits)}&format=1"
    )

    status, _, body, _, _ = await http_client.request(
        "GET", url, timeout=10, retries=1
    )
    if status in (401, 403):
        raise RuntimeError("API INVALID OR BLOCKED")
    if status == 429:
        raise RuntimeError("RATE LIMITED")
    if status != 200:
        raise RuntimeError(f"HTTP {status}")

    data = decode_json(body)
    if data.get("error"):
        raise RuntimeError(str(data["error"]))

    return data


async def search_phone(ctx: SearchContext) -> Dict[str, Any]:
    ctx_started = time.perf_counter()
    ctx.log("NORMALIZER", "Phone normalized")
    normalized = normalize_query(ctx.query, "phone")
    ctx.normalized_query = normalized

    result: Dict[str, Any] = {
        "type": "phone",
        "query": ctx.query,
        "normalized_query": normalized,
        "sources": {},
    }

    try:
        parsed = phonenumbers.parse(normalized, None if normalized.startswith("+") else "RU")
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)
        phone_data = {
            "valid": valid,
            "possible": possible,
            "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "country_code": parsed.country_code,
            "national_number": str(parsed.national_number),
        }
        for key, fn in [
            ("country", lambda: geocoder.country_name_for_number(parsed, "ru")),
            ("region",  lambda: geocoder.description_for_number(parsed, "ru")),
            ("carrier", lambda: carrier.name_for_number(parsed, "ru")),
        ]:
            try:
                v = fn()
                if v: phone_data[key] = v
            except Exception: pass
        try:
            zones = list(timezone.time_zones_for_number(parsed))
            if zones: phone_data["timezones"] = zones
        except Exception: pass
        type_map = {
            phonenumbers.PhoneNumberType.FIXED_LINE: "FIXED_LINE",
            phonenumbers.PhoneNumberType.MOBILE: "MOBILE",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
            phonenumbers.PhoneNumberType.TOLL_FREE: "TOLL_FREE",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
            phonenumbers.PhoneNumberType.VOIP: "VOIP",
            phonenumbers.PhoneNumberType.UNKNOWN: "UNKNOWN",
        }
        phone_data["number_type"] = type_map.get(phonenumbers.number_type(parsed), "UNKNOWN")
        result.update(phone_data)
        result["sources"]["phonenumbers"] = {"status": STATUS_SUCCESS, "data": phone_data}
        ctx.sources.append(SourceResult(
            source="phonenumbers", category="PHONE",
            status=STATUS_SUCCESS, duration_ms=0,
            retrieved_at=now_iso(), data=phone_data))
    except Exception as exc:
        result["sources"]["phonenumbers"] = {"status": STATUS_FAILED, "error": clamp_text(exc)}
        ctx.sources.append(SourceResult(
            source="phonenumbers", category="PHONE",
            status=STATUS_FAILED, duration_ms=0,
            retrieved_at=now_iso(), error=clamp_text(exc)))

    kody_started = time.perf_counter()
    try:
        kody_data = await asyncio.wait_for(_fetch_kody_su(normalized), timeout=12)
        duration_ms = (time.perf_counter() - kody_started) * 1000
        kody_status = kody_data.get("status", STATUS_UNKNOWN)
        source_data = kody_data.get("data", {}) or {}
        source_error = kody_data.get("error")
        result.update(source_data)
        result["sources"]["kody.su"] = {
            "status": kody_status,
            "duration_ms": round(duration_ms, 2),
            "data": source_data,
        }
        ctx.sources.append(SourceResult(
            source="KODY.SU", category="PHONE",
            status=kody_status, duration_ms=duration_ms,
            retrieved_at=now_iso(), data=source_data, error=source_error))
    except asyncio.TimeoutError:
        duration_ms = (time.perf_counter() - kody_started) * 1000
        result["sources"]["kody.su"] = {"status": STATUS_TIMEOUT, "error": "TIMEOUT"}
        ctx.sources.append(SourceResult(
            source="KODY.SU", category="PHONE",
            status=STATUS_TIMEOUT, duration_ms=duration_ms,
            retrieved_at=now_iso(), error="TIMEOUT"))
    except Exception as exc:
        duration_ms = (time.perf_counter() - kody_started) * 1000
        result["sources"]["kody.su"] = {"status": STATUS_FAILED, "error": clamp_text(exc)}
        ctx.sources.append(SourceResult(
            source="KODY.SU", category="PHONE",
            status=STATUS_FAILED, duration_ms=duration_ms,
            retrieved_at=now_iso(), error=clamp_text(exc)))

    e164 = result.get("e164", normalized)
    digits = re.sub(r"\D", "", str(e164))
    result["telegram"] = f"https://t.me/+{digits}"
    result["whatsapp"] = f"https://wa.me/{digits}"
    result["viber"] = f"viber://chat?number=%2B{digits}"

    result.setdefault("kody_su_country", "UNKNOWN")
    result.setdefault("kody_su_region", "UNKNOWN")
    result.setdefault("kody_su_city", "UNKNOWN")
    result.setdefault("kody_su_operator", "UNKNOWN")
    result.setdefault("kody_su_sim_model", "UNKNOWN")
    result.setdefault("kody_su_local_time", "UNKNOWN")

    result["source_count"] = len(result["sources"])
    result["success_count"] = sum(
        1 for s in result["sources"].values() if s.get("status") == STATUS_SUCCESS)
    result["confidence"] = (
        "HIGH" if result["success_count"] >= 2
        else "LOW" if result["success_count"] == 1
        else "UNKNOWN")
    result["duration_ms"] = round((time.perf_counter() - ctx_started) * 1000, 2)

    return {"summary": result, "sources": [s.to_dict() for s in ctx.sources]}

async def search_email(ctx: SearchContext) -> Dict[str, Any]:
    ctx.log("NORMALIZER", "Email normalized")

    tasks = [
        run_source(
            ctx,
            "email-local",
            lambda: email_local_source(ctx),
        ),
        run_source(
            ctx,
            "google-dns-email",
            lambda: email_dns_source(ctx),
        ),
    ]

    results = await asyncio.gather(*tasks)

    hibp_result = await run_source(
        ctx,
        "hibp",
        lambda: email_hibp_source(ctx),
    )
    results.append(hibp_result)

    summary: Dict[str, Any] = {
        "email": normalize_query(ctx.query, "email"),
    }

    for result in results:
        if result.status == STATUS_SUCCESS:
            summary.update(result.data)

    return {
        "summary": summary,
        "sources": [s.to_dict() for s in ctx.sources],
    }


# ============================================================================
# IP PIPELINE
# ============================================================================

async def ipwho_source(ctx: SearchContext) -> Dict[str, Any]:
    ip = ctx.normalized_query
    ipaddress.ip_address(ip)

    url = f"https://ipwho.is/{quote(ip)}"
    status, _, body, _, final_url = await http_client.request(
        "GET",
        url,
        timeout=8,
    )

    if status != 200:
        raise RuntimeError(f"HTTP {status}")

    payload = decode_json(body)

    if payload.get("success") is False:
        return {}

    fields = [
        "ip",
        "continent",
        "country",
        "country_code",
        "region",
        "city",
        "latitude",
        "longitude",
        "postal",
        "connection",
        "timezone",
        "flag",
        "currency",
    ]

    clean = {field: payload.get(field) for field in fields if field in payload}

    if isinstance(clean.get("connection"), dict):
        connection = clean["connection"]
        clean["connection"] = {
            "asn": connection.get("asn"),
            "org": connection.get("org"),
            "isp": connection.get("isp"),
            "domain": connection.get("domain"),
        }

    clean["source_url"] = final_url
    return clean


async def reverse_dns_source(ctx: SearchContext) -> Dict[str, Any]:
    ip = ctx.normalized_query
    ipaddress.ip_address(ip)

    try:
        hostname, aliases, addresses = await asyncio.to_thread(
            socket.gethostbyaddr,
            ip,
        )
        return {
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }
    except Exception as exc:
        return {
            "reverse_dns_status": "NO_DATA",
            "error": clamp_text(exc),
        }


async def search_ip(ctx: SearchContext) -> Dict[str, Any]:
    ctx.log("NORMALIZER", "IP validated")

    await asyncio.gather(
        run_source(ctx, "ipwho.is", lambda: ipwho_source(ctx)),
        run_source(ctx, "reverse-dns", lambda: reverse_dns_source(ctx)),
    )

    summary: Dict[str, Any] = {
        "ip": ctx.normalized_query,
    }

    for result in ctx.sources:
        if result.status == STATUS_SUCCESS:
            summary.update(result.data)

    # Clarification for UI: geo is approximate network geolocation.
    summary["geo_note"] = (
        "IP geolocation is approximate network/resource location, "
        "not an exact physical location of a person."
    )

    return {
        "summary": summary,
        "sources": [s.to_dict() for s in ctx.sources],
    }


# ============================================================================
# DNS PIPELINE
# ============================================================================

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"]


async def doh_query(
    resolver_url: str,
    domain: str,
    record_type: str,
) -> Dict[str, Any]:
    if resolver_url == "cloudflare":
        url = (
            "https://cloudflare-dns.com/dns-query"
            f"?name={quote(domain)}&type={record_type}"
        )
        headers = {
            "Accept": "application/dns-json",
        }
    else:
        url = (
            "https://dns.google/resolve"
            f"?name={quote(domain)}&type={record_type}"
        )
        headers = {}

    status, _, body, latency_ms, final_url = await http_client.request(
        "GET",
        url,
        timeout=8,
        retries=1,
        headers=headers,
    )

    if status != 200:
        raise RuntimeError(f"HTTP {status}")

    payload = decode_json(body)

    return {
        "record_type": record_type,
        "answers": payload.get("Answer", []),
        "status_code": payload.get("Status"),
        "latency_ms": round(latency_ms, 2),
        "source_url": final_url,
    }


async def dns_cloudflare_source(ctx: SearchContext) -> Dict[str, Any]:
    domain = ctx.normalized_query
    if not is_valid_domain(domain):
        raise ValueError("Invalid domain")

    records: Dict[str, Any] = {}

    for record_type in DNS_TYPES:
        try:
            records[record_type] = await doh_query(
                "cloudflare",
                domain,
                record_type,
            )
        except Exception as exc:
            records[record_type] = {
                "status": "UNKNOWN",
                "error": clamp_text(exc),
            }

    return {
        "domain": domain,
        "resolver": "Cloudflare DNS over HTTPS",
        "records": records,
    }


async def dns_google_source(ctx: SearchContext) -> Dict[str, Any]:
    domain = ctx.normalized_query
    if not is_valid_domain(domain):
        raise ValueError("Invalid domain")

    records: Dict[str, Any] = {}

    for record_type in ["A", "AAAA", "MX", "NS"]:
        try:
            records[record_type] = await doh_query(
                "google",
                domain,
                record_type,
            )
        except Exception as exc:
            records[record_type] = {
                "status": "UNKNOWN",
                "error": clamp_text(exc),
            }

    return {
        "domain": domain,
        "resolver": "Google Public DNS over HTTPS",
        "records": records,
    }


async def search_dns(ctx: SearchContext) -> Dict[str, Any]:
    await asyncio.gather(
        run_source(
            ctx,
            "cloudflare-dns",
            lambda: dns_cloudflare_source(ctx),
        ),
        run_source(
            ctx,
            "google-dns",
            lambda: dns_google_source(ctx),
        ),
    )

    return {
        "summary": {
            "domain": ctx.normalized_query,
        },
        "sources": [s.to_dict() for s in ctx.sources],
    }


# ============================================================================
# DOMAIN / CERTIFICATE PIPELINE
# ============================================================================

async def crt_source(ctx: SearchContext) -> Dict[str, Any]:
    domain = ctx.normalized_query
    if not is_valid_domain(domain):
        raise ValueError("Invalid domain")

    url = (
        "https://crt.sh/?q="
        f"{quote('%.' + domain)}&output=json"
    )

    status, _, body, _, final_url = await http_client.request(
        "GET",
        url,
        timeout=15,
        retries=2,
    )

    if status != 200:
        raise RuntimeError(f"HTTP {status}")

    payload = decode_json(body)

    names = set()

    for entry in payload:
        value = entry.get("name_value", "")
        for name in value.splitlines():
            normalized = name.strip().lower()
            if normalized and not normalized.startswith("*."):
                names.add(normalized)

    return {
        "domain": domain,
        "subdomains": sorted(names)[:200],
        "count": len(names),
        "source_url": final_url,
    }


async def rdap_source(ctx: SearchContext) -> Dict[str, Any]:
    domain = ctx.normalized_query
    if not is_valid_domain(domain):
        raise ValueError("Invalid domain")

    url = f"https://rdap.org/domain/{quote(domain)}"

    status, _, body, _, final_url = await http_client.request(
        "GET",
        url,
        timeout=12,
        retries=1,
    )

    if status == 404:
        return {}

    if status != 200:
        raise RuntimeError(f"HTTP {status}")

    payload = decode_json(body)

    events = []
    for event in payload.get("events", []):
        events.append(
            {
                "event_action": event.get("eventAction"),
                "event_date": event.get("eventDate"),
            }
        )

    nameservers = []
    for ns in payload.get("nameservers", []):
        name = ns.get("ldhName")
        if name:
            nameservers.append(name)

    return {
        "domain": payload.get("ldhName") or domain,
        "status": payload.get("status", []),
        "events": events,
        "nameservers": nameservers,
        "handle": payload.get("handle"),
        "source_url": final_url,
    }


async def search_domain(ctx: SearchContext) -> Dict[str, Any]:
    await asyncio.gather(
        run_source(ctx, "crt.sh", lambda: crt_source(ctx)),
        run_source(ctx, "rdap", lambda: rdap_source(ctx)),
        run_source(ctx, "cloudflare-dns", lambda: dns_cloudflare_source(ctx)),
    )

    summary: Dict[str, Any] = {
        "domain": ctx.normalized_query,
    }

    for result in ctx.sources:
        if result.status == STATUS_SUCCESS:
            for key, value in result.data.items():
                if key != "source_url":
                    summary[key] = value

    return {
        "summary": summary,
        "sources": [s.to_dict() for s in ctx.sources],
    }


# ============================================================================
# URL / HTTP PIPELINE
# ============================================================================

def validate_public_http_url(url: str) -> str:
    value = url.strip()

    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) URLs are allowed")

    if not parsed.hostname:
        raise ValueError("Missing hostname")

    return value


async def http_source(ctx: SearchContext) -> Dict[str, Any]:
    url = validate_public_http_url(ctx.query)

    status, headers, body, latency_ms, final_url = await http_client.request(
        "GET",
        url,
        timeout=HTTP_TIMEOUT_SECONDS,
        retries=1,
    )

    content_type = headers.get("content-type", "")

    text_preview = ""
    if "text" in content_type or "json" in content_type or "javascript" in content_type:
        text_preview = body[:10_000].decode("utf-8", errors="replace")

    return {
        "requested_url": url,
        "final_url": final_url,
        "status_code": status,
        "latency_ms": round(latency_ms, 2),
        "content_type": content_type,
        "content_length_bytes": len(body),
        "headers": {
            key.lower(): clamp_text(value, 500)
            for key, value in headers.items()
        },
        "body_preview": text_preview,
    }


async def search_url(ctx: SearchContext) -> Dict[str, Any]:
    await run_source(
        ctx,
        "http",
        lambda: http_source(ctx),
    )

    domain = extract_domain(validate_public_http_url(ctx.query))
    ctx.normalized_query = validate_public_http_url(ctx.query)

    # Also add DNS intelligence for the host.
    dns_ctx = SearchContext(
        search_id=ctx.search_id,
        query=domain,
        normalized_query=domain,
        target_type="domain",
        started_at=ctx.started_at,
    )

    dns_result = await search_dns(dns_ctx)

    for source in dns_ctx.sources:
        ctx.sources.append(source)

    summary: Dict[str, Any] = {
        "url": ctx.normalized_query,
        "host": domain,
    }

    for source in ctx.sources:
        if source.status == STATUS_SUCCESS:
            summary.update(source.data)

    summary["dns"] = dns_result.get("summary", {})

    return {
        "summary": summary,
        "sources": [s.to_dict() for s in ctx.sources],
    }


# ============================================================================
# USERNAME / PUBLIC PROFILE AVAILABILITY
# ============================================================================

def valid_public_username(value: str) -> str:
    username = value.lstrip("@").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        raise ValueError("Invalid username format")
    return username


async def username_site_source(
    ctx: SearchContext,
    site_name: str,
    template: str,
) -> Dict[str, Any]:
    username = valid_public_username(ctx.query)
    url = template.format(username=quote(username, safe="._-"))

    status, _, body, _, final_url = await http_client.request(
        "GET",
        url,
        timeout=6,
        retries=1,
    )

    if status == 404:
        return {
            "site": site_name,
            "profile_status": "NOT_FOUND",
            "url": url,
        }

    if status in {401, 403, 429}:
        return {
            "site": site_name,
            "profile_status": "BLOCKED",
            "url": url,
            "http_status": status,
        }

    if 200 <= status < 300:
        return {
            "site": site_name,
            "profile_status": "PUBLIC_PAGE",
            "url": url,
            "final_url": final_url,
            "content_length": len(body),
        }

    return {
        "site": site_name,
        "profile_status": "UNKNOWN",
        "url": url,
        "http_status": status,
    }


async def search_username(ctx: SearchContext) -> Dict[str, Any]:
    valid_public_username(ctx.query)

    tasks = []
    for name, template in SAFE_USERNAME_SITES:
        tasks.append(
            run_source(
                ctx,
                f"username:{name}",
                lambda n=name, t=template: username_site_source(ctx, n, t),
            )
        )

    # Concurrency is already protected by the shared HTTP semaphore.
    await asyncio.gather(*tasks)

    found = []
    blocked = []
    not_found = []
    unknown = []

    for source in ctx.sources:
        status_value = source.data.get("profile_status")
        if status_value == "PUBLIC_PAGE":
            found.append(source.data)
        elif status_value == "BLOCKED":
            blocked.append(source.data)
        elif status_value == "NOT_FOUND":
            not_found.append(source.data)
        else:
            unknown.append(source.data)

    return {
        "summary": {
            "username": valid_public_username(ctx.query),
            "public_profile_checks": len(ctx.sources),
            "public_pages": found,
            "blocked": blocked,
            "not_found": not_found,
            "unknown": unknown,
        },
        "sources": [s.to_dict() for s in ctx.sources],
        "privacy_note": (
            "This module checks only public profile page availability. "
            "It does not attempt to discover private data, hidden account "
            "metadata or access-restricted information."
        ),
    }


# ============================================================================
# CRYPTO ADDRESS — PUBLIC CHAIN METADATA ONLY
# ============================================================================

def detect_crypto_type(address: str) -> str:
    value = address.strip()

    if re.fullmatch(r"(bc1|[13])[A-Za-z0-9]{20,90}", value):
        return "BTC"

    if re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
        return "EVM"

    return "UNKNOWN"


async def crypto_source(ctx: SearchContext) -> Dict[str, Any]:
    address = ctx.normalized_query
    crypto_type = detect_crypto_type(address)

    if crypto_type == "BTC":
        url = f"https://blockstream.info/api/address/{quote(address, safe='')}"
        status, _, body, _, final_url = await http_client.request(
            "GET",
            url,
            timeout=12,
            retries=1,
        )

        if status != 200:
            raise RuntimeError(f"HTTP {status}")

        payload = decode_json(body)
        chain_stats = payload.get("chain_stats", {})
        mempool_stats = payload.get("mempool_stats", {})

        return {
            "address": address,
            "network_type": "BTC",
            "tx_count_chain": chain_stats.get("tx_count"),
            "funded_txo_sum": chain_stats.get("funded_txo_sum"),
            "spent_txo_sum": chain_stats.get("spent_txo_sum"),
            "mempool_tx_count": mempool_stats.get("tx_count"),
            "source_url": final_url,
        }

    if crypto_type == "EVM":
        # No fake balance. Without a configured provider key, explicitly
        # report the limitation rather than pretending to have chain data.
        return {
            "address": address,
            "network_type": "EVM",
            "status": STATUS_NOT_CONFIGURED,
            "note": "No EVM provider configured.",
        }

    return {}


async def search_crypto(ctx: SearchContext) -> Dict[str, Any]:
    await run_source(
        ctx,
        "blockchain-public",
        lambda: crypto_source(ctx),
    )

    summary = {
        "address": ctx.normalized_query,
        "type": detect_crypto_type(ctx.normalized_query),
    }

    for source in ctx.sources:
        if source.status == STATUS_SUCCESS:
            summary.update(source.data)

    return {
        "summary": summary,
        "sources": [s.to_dict() for s in ctx.sources],
    }


# ============================================================================
# PASSWORD STRENGTH — LOCAL ONLY
# ============================================================================

def password_strength(password: str) -> Dict[str, Any]:
    # Never persist this value, never log it and never send it over the network.
    length = len(password)

    categories = 0
    categories += 1 if any(c.islower() for c in password) else 0
    categories += 1 if any(c.isupper() for c in password) else 0
    categories += 1 if any(c.isdigit() for c in password) else 0
    categories += 1 if any(c in string.punctuation for c in password) else 0

    score = 0

    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    score += min(categories, 2)

    if length < 8:
        level = "VERY_WEAK"
    elif score <= 2:
        level = "WEAK"
    elif score <= 3:
        level = "MEDIUM"
    elif score <= 4:
        level = "STRONG"
    else:
        level = "VERY_STRONG"

    warnings = []

    if length < 12:
        warnings.append("Use a longer passphrase.")
    if categories < 3:
        warnings.append("Use more than one character class.")
    if len(set(password)) < max(4, length // 3):
        warnings.append("Password contains substantial character repetition.")

    return {
        "length": length,
        "score": score,
        "level": level,
        "warnings": warnings,
    }


# ============================================================================
# SSL PIPELINE
# ============================================================================

def ssl_certificate_sync(domain: str) -> Dict[str, Any]:
    domain = extract_domain(domain)

    context = ssl.create_default_context()

    with socket.create_connection((domain, 443), timeout=8) as raw_socket:
        with context.wrap_socket(
            raw_socket,
            server_hostname=domain,
        ) as tls_socket:
            certificate = tls_socket.getpeercert()

            subject = {}
            for part in certificate.get("subject", []):
                for key, value in part:
                    subject[key] = value

            issuer = {}
            for part in certificate.get("issuer", []):
                for key, value in part:
                    issuer[key] = value

            return {
                "domain": domain,
                "subject": subject,
                "issuer": issuer,
                "serial_number": certificate.get("serialNumber"),
                "not_before": certificate.get("notBefore"),
                "not_after": certificate.get("notAfter"),
                "san": certificate.get("subjectAltName", []),
                "version": certificate.get("version"),
                "cipher": tls_socket.cipher(),
                "tls_version": tls_socket.version(),
            }


# ============================================================================
# PORT / PING / CONNECTIVITY TOOLS
# ============================================================================

def check_port_sync(host: str, port: int) -> Dict[str, Any]:
    started = time.perf_counter()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(4)
        status = sock.connect_ex((host, port))

    duration_ms = (time.perf_counter() - started) * 1000

    return {
        "host": host,
        "port": port,
        "status": "OPEN" if status == 0 else "CLOSED_OR_FILTERED",
        "latency_ms": round(duration_ms, 2),
    }


def ping_dns_sync(host: str) -> Dict[str, Any]:
    started = time.perf_counter()
    address = socket.gethostbyname(host)
    duration_ms = (time.perf_counter() - started) * 1000

    return {
        "host": host,
        "resolved_ip": address,
        "resolution_time_ms": round(duration_ms, 2),
    }


# ============================================================================
# SEARCH SNAPSHOT / CORRELATION
# ============================================================================

def calculate_confidence(sources: List[SourceResult]) -> str:
    successful = [item for item in sources if item.status == STATUS_SUCCESS]

    if len(successful) >= 3:
        return "HIGH"
    if len(successful) == 2:
        return "MEDIUM"
    if len(successful) == 1:
        return "LOW"
    return "UNKNOWN"


def build_summary(ctx: SearchContext) -> Dict[str, Any]:
    success_count = sum(
        1 for source in ctx.sources
        if source.status == STATUS_SUCCESS
    )

    error_count = sum(
        1
        for source in ctx.sources
        if source.status in {
            STATUS_FAILED,
            STATUS_TIMEOUT,
            STATUS_BLOCKED,
        }
    )

    return {
        "search_id": ctx.search_id,
        "target_type": ctx.target_type,
        "query": ctx.query,
        "normalized_query": ctx.normalized_query,
        "source_count": len(ctx.sources),
        "success_count": success_count,
        "error_count": error_count,
        "result_count": sum(
            len(source.data)
            for source in ctx.sources
            if source.status == STATUS_SUCCESS
        ),
        "confidence": calculate_confidence(ctx.sources),
    }


def correlate_sources(ctx: SearchContext) -> Dict[str, Any]:
    """Merge repeated values only when sources explicitly returned them."""
    occurrences: Dict[str, List[str]] = {}

    for source in ctx.sources:
        if source.status != STATUS_SUCCESS:
            continue

        for key, value in source.data.items():
            if isinstance(value, (str, int, float)):
                token = f"{key}:{value}"
                occurrences.setdefault(token, []).append(source.source)

    confirmed = []

    for token, sources in occurrences.items():
        if len(sources) >= 2:
            key, value = token.split(":", 1)
            confirmed.append(
                {
                    "field": key,
                    "value": value,
                    "sources": sources,
                    "support_count": len(sources),
                }
            )

    return {
        "confirmed_matches": confirmed,
        "count": len(confirmed),
    }


# ============================================================================
# UNIVERSAL SEARCH DISPATCH
# ============================================================================

async def dispatch_search(ctx: SearchContext) -> Dict[str, Any]:
    ctx.log("DETECT", f"Type: {ctx.target_type}")

    if ctx.target_type == "phone":
        return await search_phone(ctx)

    if ctx.target_type == "email":
        return await search_email(ctx)

    if ctx.target_type == "ip":
        return await search_ip(ctx)

    if ctx.target_type == "domain":
        return await search_domain(ctx)

    if ctx.target_type == "url":
        return await search_url(ctx)

    if ctx.target_type == "username":
        return await search_username(ctx)

    if ctx.target_type == "crypto":
        return await search_crypto(ctx)

    raise ValueError(f"Unsupported search type: {ctx.target_type}")


async def perform_search(
    query: str,
    user_id: str = "local",
) -> Dict[str, Any]:
    started = time.perf_counter()

    target_type = detect_target_type(query)
    normalized = normalize_query(query, target_type)

    search_id = (
        f"INV-{datetime.now().strftime('%Y%m%d')}-"
        f"{uuid.uuid4().hex[:12].upper()}"
    )

    ctx = SearchContext(
        search_id=search_id,
        query=query,
        normalized_query=normalized,
        target_type=target_type,
        started_at=now_iso(),
    )

    ctx.log("SEARCH", "Search initialized")
    add_runtime_log("SEARCH", f"{search_id} started")

    try:
        result = await dispatch_search(ctx)

        ctx.log("CORRELATION", "Correlation completed")
        correlation = correlate_sources(ctx)
        result["correlation"] = correlation

        summary = build_summary(ctx)
        result["summary"].update(summary)

        duration_ms = (time.perf_counter() - started) * 1000

        result["search"] = {
            "search_id": search_id,
            "timestamp": ctx.started_at,
            "duration_ms": round(duration_ms, 2),
            "status": STATUS_SUCCESS,
        }

        result["timeline"] = ctx.timeline
        result["logs"] = ctx.logs

        db.save_search(
            search_id=search_id,
            user_id=user_id,
            search_type=target_type,
            original_query=query,
            normalized_query=normalized,
            duration_ms=duration_ms,
            status=STATUS_SUCCESS,
            source_count=len(ctx.sources),
            success_count=sum(
                s.status == STATUS_SUCCESS for s in ctx.sources
            ),
            error_count=sum(
                s.status in {
                    STATUS_FAILED,
                    STATUS_TIMEOUT,
                    STATUS_BLOCKED,
                }
                for s in ctx.sources
            ),
            result_count=summary["result_count"],
            snapshot=result,
        )

        ctx.log("DATABASE", "Search saved")
        add_runtime_log("DATABASE", f"{search_id} saved")
        ctx.log("SEARCH", "Completed")

        return result

    except Exception as exc:
        duration_ms = (time.perf_counter() - started) * 1000
        error_text = clamp_text(exc)

        failure_snapshot = {
            "search": {
                "search_id": search_id,
                "timestamp": ctx.started_at,
                "duration_ms": round(duration_ms, 2),
                "status": STATUS_FAILED,
            },
            "summary": {
                "search_id": search_id,
                "target_type": target_type,
                "query": query,
                "normalized_query": normalized,
            },
            "error": error_text,
            "sources": [item.to_dict() for item in ctx.sources],
            "timeline": ctx.timeline,
            "logs": ctx.logs,
        }

        db.save_search(
            search_id=search_id,
            user_id=user_id,
            search_type=target_type,
            original_query=query,
            normalized_query=normalized,
            duration_ms=duration_ms,
            status=STATUS_FAILED,
            source_count=len(ctx.sources),
            success_count=sum(
                s.status == STATUS_SUCCESS for s in ctx.sources
            ),
            error_count=len(ctx.sources),
            result_count=0,
            snapshot=failure_snapshot,
        )

        add_runtime_log("SEARCH", f"{search_id} failed")
        raise


# ============================================================================
# REPORT EXPORT
# ============================================================================

def export_to_json(snapshot: Dict[str, Any]) -> str:
    return json.dumps(
        snapshot,
        ensure_ascii=False,
        indent=2,
    )


def export_to_txt(snapshot: Dict[str, Any]) -> str:
    lines: List[str] = []

    search = snapshot.get("search", {})
    summary = snapshot.get("summary", {})

    lines.append("BLACKBOX OSINT REPORT")
    lines.append("=" * 60)
    lines.append(f"Search ID: {search.get('search_id', 'UNKNOWN')}")
    lines.append(f"Type: {summary.get('target_type', 'UNKNOWN')}")
    lines.append(f"Query: {summary.get('query', 'UNKNOWN')}")
    lines.append(f"Status: {search.get('status', 'UNKNOWN')}")
    lines.append(f"Duration: {search.get('duration_ms', 0)} ms")
    lines.append("")

    lines.append("SUMMARY")
    lines.append("-" * 60)

    for key, value in summary.items():
        if key in {"query"}:
            continue
        lines.append(f"{key}: {value}")

    lines.append("")
    lines.append("SOURCES")
    lines.append("-" * 60)

    for source in snapshot.get("sources", []):
        lines.append(
            f"{source.get('source')}: "
            f"{source.get('status')} "
            f"{source.get('duration_ms', 0)}ms"
        )

    return "\n".join(lines)


def export_to_csv(snapshot: Dict[str, Any]) -> str:
    rows = [
        ("field", "value"),
        ("search_id", snapshot.get("search", {}).get("search_id")),
        ("target_type", snapshot.get("summary", {}).get("target_type")),
        ("query", snapshot.get("summary", {}).get("query")),
        ("status", snapshot.get("search", {}).get("status")),
        ("duration_ms", snapshot.get("search", {}).get("duration_ms")),
    ]

    output = []
    for field_name, value in rows:
        output.append(
            [field_name, json.dumps(value, ensure_ascii=False)]
        )

    from io import StringIO

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerows(output)
    return buffer.getvalue()


def export_to_html(snapshot: Dict[str, Any]) -> str:
    search = snapshot.get("search", {})
    summary = snapshot.get("summary", {})

    def esc(value: Any) -> str:
        return html.escape(str(value))

    source_rows = []

    for source in snapshot.get("sources", []):
        source_rows.append(
            "<tr>"
            f"<td>{esc(source.get('source'))}</td>"
            f"<td>{esc(source.get('status'))}</td>"
            f"<td>{esc(source.get('duration_ms'))} ms</td>"
            f"<td>{esc(source.get('error') or '')}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Blackbox OSINT Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ font-family: system-ui, sans-serif; margin: 32px; line-height: 1.5; }}
.card {{ border:1px solid #ccc; border-radius:12px; padding:16px; margin:16px 0; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ border-bottom:1px solid #ddd; padding:10px; text-align:left; vertical-align:top; }}
code,pre {{ white-space:pre-wrap; word-break:break-word; }}
.badge {{ padding:4px 8px; border-radius:999px; background:#eee; }}
</style>
</head>
<body>
<h1>Blackbox OSINT Report</h1>

<div class="card">
<h2>Search</h2>
<p><strong>ID:</strong> {esc(search.get('search_id'))}</p>
<p><strong>Type:</strong> {esc(summary.get('target_type'))}</p>
<p><strong>Query:</strong> {esc(summary.get('query'))}</p>
<p><strong>Status:</strong>
<span class="badge">{esc(search.get('status'))}</span></p>
<p><strong>Duration:</strong> {esc(search.get('duration_ms'))} ms</p>
</div>

<div class="card">
<h2>Sources</h2>
<table>
<thead><tr><th>Source</th><th>Status</th><th>Duration</th><th>Error</th></tr></thead>
<tbody>
{''.join(source_rows)}
</tbody>
</table>
</div>

<div class="card">
<h2>Structured Result</h2>
<pre>{esc(json.dumps(snapshot.get('summary', {}), ensure_ascii=False, indent=2))}</pre>
</div>

<div class="card">
<h2>Timeline</h2>
<pre>{esc(json.dumps(snapshot.get('timeline', []), ensure_ascii=False, indent=2))}</pre>
</div>
</body>
</html>
"""


EXPORT_DIR = BASE_DIR / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def create_export(search_id: str, export_format: str) -> Path:
    record = db.get_search(search_id)

    if not record:
        raise FileNotFoundError("Search not found")

    snapshot = record["snapshot"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", search_id)
    path = EXPORT_DIR / f"{safe_id}_{timestamp}.{export_format}"

    if export_format == "json":
        content = export_to_json(snapshot)
    elif export_format == "txt":
        content = export_to_txt(snapshot)
    elif export_format == "csv":
        content = export_to_csv(snapshot)
    elif export_format == "html":
        content = export_to_html(snapshot)
    else:
        raise ValueError("Unsupported export format")

    path.write_text(content, encoding="utf-8")
    return path


# ============================================================================
# FASTAPI LIFECYCLE
# ============================================================================

@asynccontextmanager
async def lifespan(_: FastAPI):
    add_runtime_log("SYSTEM", "Starting backend")
    await http_client.start()
    add_runtime_log("SYSTEM", "HTTP client ready")
    yield
    add_runtime_log("SYSTEM", "Stopping backend")
    await http_client.close()


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# BASIC ENDPOINTS
# ============================================================================

@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
        "database": str(DATABASE_PATH),
        "history_persistent": True,
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "timestamp": now_iso(),
        "database_exists": DATABASE_PATH.exists(),
        "http_client_ready": http_client.session is not None,
    }


@app.get("/api/config")
async def api_config() -> Dict[str, Any]:
    api_flags = {}

    for env_name in [
        "HIBP_API_KEY",
        "NUMVERIFY_API_KEY",
        "GOOGLE_SAFE_BROWSING_API_KEY",
    ]:
        api_flags[env_name] = (
            "CONFIGURED"
            if bool(os.getenv(env_name))
            else "NOT_CONFIGURED"
        )

    return {
        "version": APP_VERSION,
        "max_concurrency": MAX_CONCURRENCY,
        "http_timeout_seconds": HTTP_TIMEOUT_SECONDS,
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        "apis": api_flags,
    }



@app.post("/api/search/phone")
async def api_search_phone(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    phone = str(body.get("phone") or body.get("number") or body.get("query") or "").strip()
    if not phone:
        raise HTTPException(400, "phone required")
    ctx = SearchContext(
        search_id=uuid.uuid4().hex,
        query=phone,
        normalized_query=normalize_query(phone, "phone"),
        target_type="phone",
        started_at=now_iso(),
    )
    result = await search_phone(ctx)
    return result.get("summary", result)


# ============================================================================
# UNIVERSAL SEARCH ENDPOINT
# ============================================================================

@app.post("/api/search")
async def api_search(request: SearchRequest) -> Dict[str, Any]:
    try:
        result = await perform_search(
            query=request.query,
            user_id=request.user_id,
        )
        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "status": STATUS_FAILED,
                "error": clamp_text(exc),
            },
        ) from exc


@app.get("/api/search/detect")
async def api_detect(query: str = Query(min_length=1, max_length=500)):
    target_type = detect_target_type(query)
    return {
        "query": query,
        "detected_type": target_type,
        "normalized": normalize_query(query, target_type),
    }



# ============================================================================
# GLOBAL SEARCH TASKS

async def _set_global_task(task_id: str, **updates: Any) -> None:
    async with GLOBAL_TASK_LOCK:
        if task_id in GLOBAL_TASKS:
            GLOBAL_TASKS[task_id].update(updates)


async def run_global_search(task_id: str, query: str, forced_type: Optional[str] = None) -> None:
    started = time.perf_counter()
    target_type = (forced_type or detect_target_type(query)).lower()

    async def progress(p, msg):
        try:
            await _set_global_task(task_id, progress=p, message=msg, status="running")
        except Exception:
            pass

    try:
        await progress(5, "Search initialized")
        await progress(15, f"Type detected: {target_type.upper()}")

        ctx = SearchContext(
            search_id=task_id,
            query=query,
            normalized_query=normalize_query(query, target_type),
            target_type=target_type,
            started_at=now_iso(),
        )

        await progress(30, f"{target_type.upper()} started")

        try:
            result = await asyncio.wait_for(dispatch_search(ctx), timeout=90)
        except asyncio.TimeoutError:
            result = {"summary": {"query": query, "error": "TIMEOUT"}, "sources": []}
        except Exception as exc:
            result = {"summary": {"query": query, "error": clamp_text(exc)}, "sources": []}

        await progress(80, "Processing result")

        result["search_id"] = task_id
        result["timeline"] = ctx.timeline
        result["logs"] = ctx.logs
        duration_ms = (time.perf_counter() - started) * 1000

        await _set_global_task(
            task_id, status="completed", progress=100, message="Completed",
            result=result.get("summary", result),
            sources=result.get("sources", []),
            completed_at=now_iso(),
            duration_ms=round(duration_ms, 2),
        )
    except Exception as exc:
        await _set_global_task(
            task_id, status="error", progress=100,
            message=clamp_text(exc), error=clamp_text(exc),
            completed_at=now_iso(),
        )
    finally:
        try:
            t = GLOBAL_TASKS.get(task_id)
            if t and t.get("status") == "running":
                await _set_global_task(
                    task_id, status="error", progress=100,
                    message="Force-completed", error="Force-completed",
                    completed_at=now_iso(),
                )
        except Exception:
            pass

@app.post("/api/global_search")
async def api_global_search(request: GlobalSearchRequest) -> Dict[str, Any]:
    query = request.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query is empty")

    target_type = (request.type or detect_target_type(query)).lower()
    aliases = {
        "PHONE": "phone",
        "EMAIL": "email",
        "USERNAME": "username",
        "IP": "ip",
        "DOMAIN": "domain",
        "URL": "url",
        "CRYPTO": "crypto",
    }
    target_type = aliases.get(target_type, target_type)

    if target_type not in {
        "phone", "email", "username", "ip", "domain", "url", "crypto",
    }:
        raise HTTPException(status_code=400, detail="Unsupported search type")

    task_id = uuid.uuid4().hex

    async with GLOBAL_TASK_LOCK:
        GLOBAL_TASKS[task_id] = {
            "task_id": task_id,
            "query": query,
            "type": target_type,
            "status": "queued",
            "progress": 0,
            "message": "Queued",
            "result": None,
            "sources": [],
            "error": None,
            "created_at": now_iso(),
        }

    asyncio.create_task(
        run_global_search(
            task_id=task_id,
            query=query,
            forced_type=target_type,
        )
    )

    return {
        "task_id": task_id,
        "type": target_type,
        "status": "queued",
    }


@app.get("/api/progress/{task_id}")
async def api_progress(task_id: str) -> Dict[str, Any]:
    async with GLOBAL_TASK_LOCK:
        task = GLOBAL_TASKS.get(task_id)

    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    return dict(task)

# ============================================================================
# HISTORY ENDPOINTS
# ============================================================================

@app.get("/api/history")
async def api_history(
    user_id: str = Query(default="local", min_length=1, max_length=128),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    search_type: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None, max_length=200),
):
    rows = db.list_searches(
        user_id=user_id,
        offset=offset,
        limit=limit,
        search_type=search_type,
        query_filter=q,
    )

    return {
        "items": rows,
        "offset": offset,
        "limit": limit,
        "total": db.count_searches(user_id),
    }


@app.get("/api/history/{search_id}")
async def api_history_open(
    search_id: str,
    user_id: str = Query(default="local", min_length=1, max_length=128),
):
    record = db.get_search(search_id)

    if not record:
        raise HTTPException(
            status_code=404,
            detail="NO DATA",
        )

    if record["user_id"] != user_id:
        raise HTTPException(
            status_code=404,
            detail="NO DATA",
        )

    return {
        "search_id": search_id,
        "metadata": {
            key: record[key]
            for key in [
                "user_id",
                "search_type",
                "original_query",
                "normalized_query",
                "timestamp",
                "duration_ms",
                "status",
                "source_count",
                "success_count",
                "error_count",
                "result_count",
            ]
        },
        "snapshot": record["snapshot"],
    }


@app.delete("/api/history")
async def api_history_delete(payload: HistoryDeleteRequest, user_id: str = "local"):
    deleted = db.delete_searches(
        user_id=user_id,
        search_ids=payload.search_ids,
    )

    return {
        "status": "SUCCESS",
        "deleted": deleted,
    }


@app.delete("/api/history/all")
async def api_history_clear(user_id: str = "local"):
    deleted = db.clear_history(user_id)
    return {
        "status": "SUCCESS",
        "deleted": deleted,
    }


# ============================================================================
# LOG ENDPOINTS
# ============================================================================

@app.get("/api/logs")
async def api_logs(limit: int = Query(default=200, ge=1, le=500)):
    return {
        "items": get_runtime_logs(limit),
        "count": len(get_runtime_logs(limit)),
    }


@app.delete("/api/logs")
async def api_logs_clear():
    clear_runtime_logs()
    return {
        "status": "SUCCESS",
    }


# ============================================================================
# SOURCE REGISTRY / HEALTH
# ============================================================================

@app.get("/api/sources")
async def api_sources():
    items = []

    for source in SOURCE_REGISTRY.values():
        item = asdict(source)
        if source.requires_api_key:
            item["api_status"] = (
                "CONFIGURED"
                if os.getenv(source.requires_api_key)
                else "NOT_CONFIGURED"
            )
        else:
            item["api_status"] = "PUBLIC"
        items.append(item)

    return {
        "sources": items,
        "health": db.list_source_health(),
    }


async def source_health_check(
    source_name: str,
) -> Dict[str, Any]:
    source = SOURCE_REGISTRY.get(source_name)

    if source is None:
        return {
            "source": source_name,
            "status": STATUS_UNKNOWN,
            "error": "SOURCE NOT REGISTERED",
        }

    if source.requires_api_key and not os.getenv(source.requires_api_key):
        return {
            "source": source_name,
            "status": STATUS_NOT_CONFIGURED,
            "error": "API NOT CONFIGURED",
        }

    if not source.health_url:
        return {
            "source": source_name,
            "status": STATUS_UNKNOWN,
            "error": "HEALTH CHECK NOT IMPLEMENTED",
        }

    started = time.perf_counter()

    try:
        status, _, _, _, final_url = await http_client.request(
            "GET",
            source.health_url,
            timeout=source.timeout,
            retries=0,
        )

        latency_ms = (time.perf_counter() - started) * 1000
        source_status = (
            STATUS_SUCCESS
            if 200 <= status < 400
            else classify_http_failure(status)
        )

        db.update_source_health(
            source_name,
            source_status,
            latency_ms,
            None if source_status == STATUS_SUCCESS else f"HTTP {status}",
        )

        return {
            "source": source_name,
            "status": source_status,
            "http_status": status,
            "latency_ms": round(latency_ms, 2),
            "url": final_url,
        }

    except asyncio.TimeoutError:
        latency_ms = (time.perf_counter() - started) * 1000
        db.update_source_health(
            source_name,
            STATUS_TIMEOUT,
            latency_ms,
            "TIMEOUT",
        )
        return {
            "source": source_name,
            "status": STATUS_TIMEOUT,
            "latency_ms": round(latency_ms, 2),
        }

    except Exception as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        db.update_source_health(
            source_name,
            STATUS_FAILED,
            latency_ms,
            clamp_text(exc),
        )
        return {
            "source": source_name,
            "status": STATUS_FAILED,
            "latency_ms": round(latency_ms, 2),
            "error": clamp_text(exc),
        }


@app.get("/api/source-health")
async def api_source_health():
    results = await asyncio.gather(
        *(source_health_check(name) for name in SOURCE_REGISTRY)
    )
    return {
        "items": results,
        "stored": db.list_source_health(),
    }


@app.post("/api/source-health/check")
async def api_source_health_check(payload: SourceCheckRequest):
    return await source_health_check(payload.source)


# ============================================================================
# SECURITY / NETWORK TOOLS
# ============================================================================

@app.post("/api/security/password-strength")
async def api_password_strength(payload: PasswordRequest):
    # Deliberately no db/logging for the raw password.
    return {
        "status": "SUCCESS",
        "result": password_strength(payload.password),
        "privacy": "Password is evaluated locally in memory and is not stored.",
    }


@app.post("/api/security/ssl")
async def api_ssl(payload: SSLRequest):
    domain = extract_domain(payload.domain)

    try:
        result = await asyncio.to_thread(
            ssl_certificate_sync,
            domain,
        )
        return {
            "status": STATUS_SUCCESS,
            "result": result,
        }
    except Exception as exc:
        return {
            "status": STATUS_FAILED,
            "result": {
                "domain": domain,
                "error": clamp_text(exc),
            },
        }


@app.post("/api/network/port")
async def api_port(payload: PortRequest):
    # Intended for systems/networks the user is authorized to test.
    try:
        result = await asyncio.to_thread(
            check_port_sync,
            payload.host,
            payload.port,
        )
        return {
            "status": STATUS_SUCCESS,
            "result": result,
        }
    except Exception as exc:
        return {
            "status": STATUS_FAILED,
            "result": {
                "host": payload.host,
                "port": payload.port,
                "error": clamp_text(exc),
            },
        }


@app.post("/api/network/ping")
async def api_ping(payload: PingRequest):
    try:
        result = await asyncio.to_thread(
            ping_dns_sync,
            payload.host,
        )
        return {
            "status": STATUS_SUCCESS,
            "result": result,
        }
    except Exception as exc:
        return {
            "status": STATUS_FAILED,
            "result": {
                "host": payload.host,
                "error": clamp_text(exc),
            },
        }


# ============================================================================
# EXPORT ENDPOINTS
# ============================================================================

@app.post("/api/export")
async def api_export(payload: ExportRequest):
    try:
        path = create_export(
            search_id=payload.search_id,
            export_format=payload.format,
        )

        return {
            "status": STATUS_SUCCESS,
            "path": str(path),
            "filename": path.name,
            "download_url": f"/api/export/{path.name}",
        }

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="NO DATA",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=clamp_text(exc),
        ) from exc


@app.get("/api/export/{filename}")
async def api_export_download(filename: str):
    safe_name = Path(filename).name
    path = EXPORT_DIR / safe_name

    if not path.exists() or not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="NO DATA",
        )

    return FileResponse(
        path,
        filename=path.name,
    )


# ============================================================================
# CACHE / RUNTIME METRICS
# ============================================================================

@app.get("/api/metrics")
async def api_metrics():
    return {
        "timestamp": now_iso(),
        "cache_entries": await cache.size(),
        "inflight_requests": len(deduper._inflight),
        "runtime_logs": len(runtime_logs),
        "database_path": str(DATABASE_PATH),
        "database_exists": DATABASE_PATH.exists(),
    }


@app.delete("/api/cache")
async def api_cache_clear():
    await cache.clear()
    add_runtime_log("CACHE", "Cache cleared")
    return {
        "status": "SUCCESS",
    }


# ============================================================================
# TESTABLE NORMALIZERS
# ============================================================================

@app.get("/api/normalize/domain")
async def api_normalize_domain(domain: str = Query(min_length=1, max_length=255)):
    normalized = normalize_query(domain, "domain")
    return {
        "original": domain,
        "normalized": normalized,
        "valid": is_valid_domain(normalized),
    }


@app.get("/api/normalize/phone")
async def api_normalize_phone(phone: str = Query(min_length=1, max_length=64)):
    normalized = normalize_phone_local(phone)
    return {
        "original": phone,
        "normalized": normalized,
        "display": format_phone_fallback(normalized),
    }


@app.get("/api/normalize/email")
async def api_normalize_email(email: str = Query(min_length=3, max_length=320)):
    normalized = normalize_query(email, "email")
    return {
        "original": email,
        "normalized": normalized,
        "valid": is_valid_email(normalized),
    }


@app.get("/api/normalize/username")
async def api_normalize_username(username: str = Query(min_length=1, max_length=80)):
    try:
        normalized = valid_public_username(username)
        valid = True
        error = None
    except Exception as exc:
        normalized = username.lstrip("@").strip()
        valid = False
        error = clamp_text(exc)

    return {
        "original": username,
        "normalized": normalized,
        "valid": valid,
        "error": error,
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(_, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": STATUS_FAILED,
            "error": exc.detail,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(_, exc: Exception):
    add_runtime_log("ERROR", "Unhandled application error")
    return JSONResponse(
        status_code=500,
        content={
            "status": STATUS_FAILED,
            "error": clamp_text(exc),
        },
    )


# ============================================================================
# SELF-CHECKS
# ============================================================================

def self_check() -> Dict[str, Any]:
    checks = {
        "database_exists": DATABASE_PATH.exists(),
        "source_registry_nonempty": bool(SOURCE_REGISTRY),
        "username_sources_nonempty": bool(SAFE_USERNAME_SITES),
        "export_directory_exists": EXPORT_DIR.exists(),
        "max_concurrency_positive": MAX_CONCURRENCY > 0,
        "http_timeout_positive": HTTP_TIMEOUT_SECONDS > 0,
        "cache_ttl_positive": CACHE_TTL_SECONDS > 0,
    }

    return {
        "status": STATUS_SUCCESS if all(checks.values()) else STATUS_FAILED,
        "checks": checks,
    }


@app.get("/api/self-check")
async def api_self_check():
    return self_check()


# ============================================================================
# COMMENTS / ARCHITECTURE MARKERS
# ============================================================================

# The next blocks are intentionally explicit rather than magical. They make
# the codebase easier to extend with additional public OSINT modules later.
#
# Recommended plugin contract:
#
#   async def plugin(ctx: SearchContext) -> Dict[str, Any]:
#       return {
#           "field": "value",
#           "source_url": "https://...",
#       }
#
# Then register it in SOURCE_REGISTRY and call it through run_source().
#
# Do not add a plugin merely to increase the line count.
# A plugin should have:
#   1. a real public source or officially documented API;
#   2. timeout handling;
#   3. error handling;
#   4. a parser;
#   5. a status;
#   6. tests;
#   7. UI integration.
#
# The backend already provides:
#   * persistent history;
#   * historical snapshots;
#   * source metadata;
#   * correlation;
#   * timeline;
#   * runtime logs;
#   * cache;
#   * de-duplication;
#   * concurrency limiting;
#   * export;
#   * source health;
#   * API configuration states.
#
# Future safe modules can be appended without rewriting working code.
#
# Example future categories:
#   DOMAIN
#   DNS
#   IP
#   HTTP
#   SSL
#   CERTIFICATE
#   EMAIL_SECURITY
#   PUBLIC_PROFILES
#   CRYPTO
#   REPORTING
#
# Avoid private-data acquisition modules, credential modules, account-takeover
# modules and any bypass of authentication or access controls.
#
# Keep all user-facing unknown states honest:
#   SUCCESS
#   FAILED
#   TIMEOUT
#   BLOCKED
#   UNKNOWN
#   NOT_CONFIGURED
#   NO_DATA
#
# Never convert one state into another just to make the UI look successful.


# ============================================================================
# TEST CASE FUNCTIONS
# ============================================================================

def _test_detect_types() -> None:
    assert detect_target_type("1.1.1.1") == "ip"
    assert detect_target_type("user@example.com") == "email"
    assert detect_target_type("example.com") == "domain"
    assert detect_target_type("https://example.com") == "url"
    assert detect_target_type("+79991234567") == "phone"
    assert detect_target_type("test_user") == "username"


def _test_normalizers() -> None:
    assert normalize_query(" USER@Example.COM ", "email") == "user@example.com"
    assert normalize_query(" @alice ", "username") == "alice"
    assert normalize_query(" HTTP://Example.COM/ ", "domain") == "example.com"


def _test_password_strength() -> None:
    weak = password_strength("abc")
    strong = password_strength("This-is-a-Long-Test-1234")
    assert weak["level"] == "VERY_WEAK"
    assert strong["level"] in {"STRONG", "VERY_STRONG"}


def _test_redaction() -> None:
    value = redact_secrets("Authorization: Bearer abc123 api_key=secret123")
    assert "abc123" not in value
    assert "secret123" not in value


def run_local_tests() -> Dict[str, Any]:
    tests = [
        ("detect_types", _test_detect_types),
        ("normalizers", _test_normalizers),
        ("password_strength", _test_password_strength),
        ("redaction", _test_redaction),
    ]

    passed = []
    failed = []

    for name, test in tests:
        try:
            test()
            passed.append(name)
        except Exception as exc:
            failed.append(
                {
                    "name": name,
                    "error": clamp_text(exc),
                }
            )

    return {
        "status": STATUS_SUCCESS if not failed else STATUS_FAILED,
        "passed": passed,
        "failed": failed,
    }


@app.get("/api/tests")
async def api_tests():
    return run_local_tests()


# ============================================================================
# DEVELOPMENT ENTRYPOINT
# ============================================================================

# ============================================================================
# 2IP.RU REPLACEMENT TOOLS — реальные публичные источники
# ============================================================================

import math as _math

class UrlBody(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

class HostBody(BaseModel):
    host: str = Field(min_length=1, max_length=255)

class IpBody(BaseModel):
    ip: str = Field(min_length=1, max_length=64)

class DomainBody(BaseModel):
    domain: str = Field(min_length=1, max_length=255)

class EmailBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)

class PortBody(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)

class PunyBody(BaseModel):
    domain: str = Field(min_length=1, max_length=255)

def _ok(result): return {"status": STATUS_SUCCESS, "result": result}
def _err(exc):   return {"status": STATUS_FAILED, "error": clamp_text(exc)}


# --- 1. My IP ---
@app.get("/api/2ip/my-ip")
async def t_my_ip():
    try:
        _, _, body, _, _ = await http_client.request("GET", "https://api.ipify.org?format=json", timeout=5)
        ip = json.loads(body.decode()).get("ip")
        _, _, body2, _, _ = await http_client.request(
            "GET", f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query", timeout=8)
        d = json.loads(body2.decode())
        return _ok({"ip": ip, **{k: d.get(k) for k in ("country","city","isp","org","as")}})
    except Exception as e: return _err(e)


# --- 2. Anonymity check ---
@app.post("/api/2ip/anonymity")
async def t_anonymity(p: IpBody):
    try: ipaddress.ip_address(p.ip)
    except ValueError: return _err("Invalid IP")
    try:
        _, _, body, _, _ = await http_client.request(
            "GET", f"http://ip-api.com/json/{p.ip}?fields=status,proxy,hosting,mobile,query", timeout=8)
        d = json.loads(body.decode())
        if d.get("status") != "success": return _err(d.get("message","failed"))
        verdict = "ANONYMOUS" if (d.get("proxy") or d.get("hosting")) else ("MOBILE" if d.get("mobile") else "RESIDENTIAL")
        return _ok({"ip": p.ip, "verdict": verdict, "proxy": d.get("proxy"),
                    "hosting": d.get("hosting"), "mobile": d.get("mobile")})
    except Exception as e: return _err(e)


# --- 3. Download time + size ---
@app.post("/api/2ip/download-info")
async def t_download_info(p: UrlBody):
    url = p.url if p.url.startswith(("http://","https://")) else "https://"+p.url
    try:
        st = time.perf_counter()
        status, headers, body, _, final = await http_client.request("GET", url, timeout=25, retries=0)
        dur = time.perf_counter() - st
        return _ok({"url": url, "final_url": final, "http_status": status,
                    "size_bytes": len(body), "size_kb": round(len(body)/1024,2),
                    "duration_seconds": round(dur,3),
                    "speed_kbps": round((len(body)/max(dur,0.001))/1024, 2),
                    "content_type": headers.get("content-type","")})
    except Exception as e: return _err(e)


# --- 4. Speed test ---
@app.get("/api/2ip/speed-test")
async def t_speed_test():
    try:
        st = time.perf_counter()
        _, _, body, _, _ = await http_client.request(
            "GET", "https://speed.cloudflare.com/__down?bytes=5000000", timeout=60, retries=0)
        dur = time.perf_counter() - st
        return _ok({"bytes": len(body), "duration_seconds": round(dur,3),
                    "speed_mbps": round((len(body)*8)/(max(dur,0.001)*1_000_000), 2),
                    "note": "Server-side measurement"})
    except Exception as e: return _err(e)


# --- 5. IP info ---
@app.post("/api/2ip/ip-info")
async def t_ip_info(p: IpBody):
    try: ipaddress.ip_address(p.ip)
    except ValueError: return _err("Invalid IP")
    try:
        _, _, body, _, _ = await http_client.request("GET", f"https://ipwho.is/{p.ip}", timeout=10)
        d = json.loads(body.decode())
        if d.get("success") is False: return _err("No data")
        return _ok({k: d.get(k) for k in
                    ("ip","country","city","region","latitude","longitude","timezone","connection")})
    except Exception as e: return _err(e)


# --- 6. Domain → IP ---
@app.post("/api/2ip/domain-ip")
async def t_domain_ip(p: DomainBody):
    try:
        _, _, body, _, _ = await http_client.request(
            "GET", f"https://dns.google/resolve?name={quote(p.domain)}&type=A", timeout=8)
        d = json.loads(body.decode())
        ips = [a.get("data") for a in d.get("Answer",[]) if a.get("type")==1]
        return _ok({"domain": p.domain, "ip_addresses": ips})
    except Exception as e: return _err(e)


# --- 7. CMS detection ---
@app.post("/api/2ip/cms")
async def t_cms(p: UrlBody):
    url = p.url if p.url.startswith(("http://","https://")) else "https://"+p.url
    try:
        _, headers, body, _, _ = await http_client.request("GET", url, timeout=12, retries=0)
        page = body[:200_000].decode("utf-8","replace").lower()
        cms = []
        sigs = {"wordpress":["wp-content","wp-includes","/wp-json/"],
                "joomla":["/components/com_","joomla"],
                "drupal":["drupalsettings","sites/default/files","/sites/all/"],
                "bitrix":["/bitrix/js/","bitrix24"],
                "opencart":["catalog/view/","route=common/home"],
                "tilda":["tildacdn.com","tilda"],
                "wix":["wix.com","wixstatic"],
                "shopify":["cdn.shopify.com","shopify"],
                "magento":["/skin/frontend/","mage/"],
                "modx":["/assets/components/","modx"],
                "laravel":["laravel_session","x-powered-by: laravel"],
                "django":["csrfmiddlewaretoken","django"],
                "nextjs":["__next","_next/static"]}
        for name, pats in sigs.items():
            if any(s in page for s in pats): cms.append(name)
        server = headers.get("server","")
        powered = headers.get("x-powered-by","")
        return _ok({"url": url, "cms": cms, "server": server, "x_powered_by": powered})
    except Exception as e: return _err(e)


# --- 8. Hosting info ---
@app.post("/api/2ip/hosting")
async def t_hosting(p: IpBody):
    try: ipaddress.ip_address(p.ip)
    except ValueError: return _err("Invalid IP")
    try:
        _, _, body, _, _ = await http_client.request(
            "GET", f"https://ipwho.is/{p.ip}?fields=success,connection,country,city", timeout=10)
        d = json.loads(body.decode())
        return _ok({"ip": p.ip, "hosting": d.get("connection",{}).get("isp"),
                    "org": d.get("connection",{}).get("org"),
                    "asn": d.get("connection",{}).get("asn"),
                    "country": d.get("country"), "city": d.get("city")})
    except Exception as e: return _err(e)


# --- 9. Distance (approx, haversine) ---
@app.post("/api/2ip/distance")
async def t_distance(p: IpBody):
    try: ipaddress.ip_address(p.ip)
    except ValueError: return _err("Invalid IP")
    try:
        _, _, b1, _, _ = await http_client.request("GET", "http://ip-api.com/json/?fields=lat,lon,city,country", timeout=8)
        src = json.loads(b1.decode())
        _, _, b2, _, _ = await http_client.request(
            "GET", f"http://ip-api.com/json/{p.ip}?fields=status,lat,lon,city,country", timeout=8)
        dst = json.loads(b2.decode())
        if dst.get("status") != "success": return _err("Target lookup failed")
        R = 6371.0
        lat1, lon1 = _math.radians(src["lat"]), _math.radians(src["lon"])
        lat2, lon2 = _math.radians(dst["lat"]), _math.radians(dst["lon"])
        dlat, dlon = lat2-lat1, lon2-lon1
        a = _math.sin(dlat/2)**2 + _math.cos(lat1)*_math.cos(lat2)*_math.sin(dlon/2)**2
        dist = 2*R*_math.asin(_math.sqrt(a))
        return _ok({"source": {"city": src.get("city"), "country": src.get("country")},
                    "target": {"ip": p.ip, "city": dst.get("city"), "country": dst.get("country")},
                    "distance_km": round(dist, 2)})
    except Exception as e: return _err(e)


# --- 10. Site info (meta + headers) ---
@app.post("/api/2ip/site-info")
async def t_site_info(p: UrlBody):
    url = p.url if p.url.startswith(("http://","https://")) else "https://"+p.url
    try:
        _, headers, body, _, final = await http_client.request("GET", url, timeout=12, retries=0)
        html = body[:300_000].decode("utf-8","replace")
        title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I|re.S)
        desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', html, re.I)
        return _ok({"url": final, "title": title.group(1).strip() if title else None,
                    "description": desc.group(1).strip() if desc else None,
                    "server": headers.get("server"), "content_type": headers.get("content-type")})
    except Exception as e: return _err(e)


# --- 11. Sites on same IP (Shodan InternetDB) ---
@app.post("/api/2ip/sites-on-ip")
async def t_sites_on_ip(p: IpBody):
    try: ipaddress.ip_address(p.ip)
    except ValueError: return _err("Invalid IP")
    try:
        _, _, body, _, _ = await http_client.request("GET", f"https://internetdb.shodan.io/{p.ip}", timeout=10)
        if body == b"{}": return _ok({"ip": p.ip, "hostnames": [], "ports": [], "cpes": [], "vulns": []})
        d = json.loads(body.decode())
        return _ok({"ip": p.ip,
                    "hostnames": d.get("hostnames",[]),
                    "ports": d.get("ports",[]),
                    "tags": d.get("tags",[]),
                    "vulns": d.get("vulns",[])})
    except Exception as e: return _err(e)


# --- 12. Domains by owner (RDAP reverse, limited) ---
@app.post("/api/2ip/domains-by-owner")
async def t_domains_by_owner(p: DomainBody):
    try:
        _, _, body, _, _ = await http_client.request("GET", f"https://rdap.org/domain/{quote(p.domain)}", timeout=12)
        d = json.loads(body.decode())
        return _ok({"domain": d.get("ldhName", p.domain),
                    "entities": [{"handle": e.get("handle"),
                                  "roles": e.get("roles",[])} for e in d.get("entities",[])],
                    "nameservers": [ns.get("ldhName") for ns in d.get("nameservers",[])]})
    except Exception as e: return _err(e)


# --- 13. Site availability ---
@app.post("/api/2ip/site-availability")
async def t_site_availability(p: UrlBody):
    url = p.url if p.url.startswith(("http://","https://")) else "https://"+p.url
    try:
        st = time.perf_counter()
        status, _, _, _, final = await http_client.request("GET", url, timeout=12, retries=0)
        dur = (time.perf_counter()-st)*1000
        return _ok({"url": final, "http_status": status,
                    "available": 200 <= status < 500,
                    "response_time_ms": round(dur, 2)})
    except Exception as e:
        return _ok({"url": url, "available": False, "error": clamp_text(e)})


# --- 14. Spam DB check (DNSBL) ---
@app.post("/api/2ip/spam-db")
async def t_spam_db(p: IpBody):
    try: ipaddress.ip_address(p.ip)
    except ValueError: return _err("Invalid IP")
    try:
        rev = ".".join(reversed(p.ip.split(".")))
        zones = ["zen.spamhaus.org","bl.spamcop.net","b.barracudacentral.org","dnsbl.sorbs.net"]
        listed = []
        for zone in zones:
            try:
                await asyncio.to_thread(socket.gethostbyname, f"{rev}.{zone}")
                listed.append(zone)
            except Exception: pass
        return _ok({"ip": p.ip, "listed_in": listed, "clean": len(listed)==0})
    except Exception as e: return _err(e)


# --- 15. Email existence (MX) ---
@app.post("/api/2ip/email-check")
async def t_email_check(p: EmailBody):
    if not is_valid_email(p.email): return _err("Invalid email format")
    domain = p.email.split("@",1)[1]
    try:
        _, _, body, _, _ = await http_client.request(
            "GET", f"https://dns.google/resolve?name={quote(domain)}&type=MX", timeout=8)
        d = json.loads(body.decode())
        mx = [a.get("data") for a in d.get("Answer",[]) if a.get("type")==15]
        return _ok({"email": p.email, "domain": domain,
                    "mx_records": mx, "accepts_email": bool(mx)})
    except Exception as e: return _err(e)


# --- 16. Computer security (proxy/VPN verdict) ---
@app.get("/api/2ip/computer-security")
async def t_computer_security():
    try:
        _, _, b1, _, _ = await http_client.request("GET", "https://api.ipify.org?format=json", timeout=5)
        ip = json.loads(b1.decode()).get("ip")
        _, _, b2, _, _ = await http_client.request(
            "GET", f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,mobile,country,isp", timeout=8)
        d = json.loads(b2.decode())
        threats = []
        if d.get("proxy"): threats.append("PROXY_DETECTED")
        if d.get("hosting"): threats.append("DATACENTER_IP")
        return _ok({"ip": ip, "country": d.get("country"), "isp": d.get("isp"),
                    "threats": threats, "safe": len(threats)==0})
    except Exception as e: return _err(e)


# --- 17. Port check ---
@app.post("/api/2ip/port-check")
async def t_port_check(p: PortBody):
    try:
        r = await asyncio.to_thread(check_port_sync, p.host, p.port)
        return _ok(r)
    except Exception as e: return _err(e)


# --- 18. File/site virus check (URLhaus) ---
@app.post("/api/2ip/site-virus")
async def t_site_virus(p: UrlBody):
    url = p.url if p.url.startswith(("http://","https://")) else "https://"+p.url
    try:
        _, _, body, _, _ = await http_client.request(
            "POST", "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url}, timeout=12)
        d = json.loads(body.decode())
        return _ok({"url": url,
                    "query_status": d.get("query_status"),
                    "threat": d.get("threat"),
                    "tags": d.get("tags",[]),
                    "date_added": d.get("date_added")})
    except Exception as e: return _err(e)


# --- 19. File virus check (VirusTotal, needs key) ---
@app.post("/api/2ip/file-virus")
async def t_file_virus(p: UrlBody):
    key = os.getenv("VIRUSTOTAL_API_KEY","").strip()
    if not key: return {"status": STATUS_NOT_CONFIGURED, "error": "VIRUSTOTAL_API_KEY not set"}
    url = p.url if p.url.startswith(("http://","https://")) else "https://"+p.url
    try:
        _, _, body, _, _ = await http_client.request(
            "POST", "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers={"x-apikey": key}, timeout=15, retries=0)
        d = json.loads(body.decode())
        return _ok({"url": url, "analysis_id": d.get("data",{}).get("id")})
    except Exception as e: return _err(e)


# --- 20. Browser relevance (info) ---
@app.get("/api/2ip/browser-relevance")
async def t_browser_relevance():
    return _ok({
        "latest_stable": {"Chrome":"131","Firefox":"133","Edge":"131","Safari":"18"},
        "note": "Client-side check — compare your browser version with the list above.",
    })


# --- 21. Punycode ---
@app.post("/api/2ip/punycode")
async def t_punycode(p: PunyBody):
    try:
        return _ok({"original": p.domain, "punycode": p.domain.encode("idna").decode("ascii")})
    except Exception as e: return _err(e)


# --- 22. Server response (headers) ---
@app.post("/api/2ip/server-response")
async def t_server_response(p: UrlBody):
    url = p.url if p.url.startswith(("http://","https://")) else "https://"+p.url
    try:
        st = time.perf_counter()
        status, headers, body, _, final = await http_client.request("GET", url, timeout=12, retries=0)
        dur = (time.perf_counter()-st)*1000
        return _ok({"url": final, "status_code": status,
                    "response_time_ms": round(dur,2),
                    "headers": {k.lower(): clamp_text(v,500) for k,v in headers.items()}})
    except Exception as e: return _err(e)


# --- 23. Domain search (RDAP) ---
@app.post("/api/2ip/domain-search")
async def t_domain_search(p: DomainBody):
    try:
        _, _, body, _, _ = await http_client.request("GET", f"https://rdap.org/domain/{quote(p.domain)}", timeout=12)
        if body == b"": return _err("Not found")
        d = json.loads(body.decode())
        return _ok({"domain": d.get("ldhName"),
                    "status": d.get("status",[]),
                    "events": d.get("events",[]),
                    "nameservers": [n.get("ldhName") for n in d.get("nameservers",[])]})
    except Exception as e: return _err(e)


# --- 24. IP by email (MX → A) ---
@app.post("/api/2ip/email-ip")
async def t_email_ip(p: EmailBody):
    if "@" not in p.email: return _err("Invalid email")
    domain = p.email.split("@",1)[1]
    try:
        _, _, b1, _, _ = await http_client.request(
            "GET", f"https://dns.google/resolve?name={quote(domain)}&type=MX", timeout=8)
        mx = [a.get("data","").rstrip(".") for a in json.loads(b1.decode()).get("Answer",[]) if a.get("type")==15]
        ips = []
        for host in mx[:5]:
            try:
                _, _, b2, _, _ = await http_client.request(
                    "GET", f"https://dns.google/resolve?name={quote(host)}&type=A", timeout=8)
                ips.extend([a.get("data") for a in json.loads(b2.decode()).get("Answer",[]) if a.get("type")==1])
            except Exception: pass
        return _ok({"email": p.email, "domain": domain, "mx_hosts": mx, "mx_ips": ips})
    except Exception as e: return _err(e)


# --- 25. Roskomnadzor block check ---
@app.post("/api/2ip/roskomnadzor")
async def t_roskomnadzor(p: DomainBody):
    try:
        _, _, body, _, _ = await http_client.request(
            "GET", f"https://reestr.rublacklist.net/api/v3/domains/?search={quote(p.domain)}",
            timeout=12)
        if not body: return _ok({"domain": p.domain, "blocked": False})
        d = json.loads(body.decode())
        blocked = bool(d)
        return _ok({"domain": p.domain, "blocked": blocked, "records": d[:3] if isinstance(d, list) else []})
    except Exception as e:
        return _ok({"domain": p.domain, "blocked": None, "note": "Service unavailable"})


# --- 26. Domain age (RDAP) ---
@app.post("/api/2ip/domain-age")
async def t_domain_age(p: DomainBody):
    try:
        _, _, body, _, _ = await http_client.request("GET", f"https://rdap.org/domain/{quote(p.domain)}", timeout=12)
        d = json.loads(body.decode())
        created = None
        for ev in d.get("events",[]):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate")
                break
        age_days = None
        if created:
            try:
                from datetime import datetime as _dt
                created_dt = _dt.fromisoformat(created.replace("Z","+00:00"))
                age_days = (_dt.now(dt_timezone.utc) - created_dt).days
            except Exception: pass
        return _ok({"domain": p.domain, "created": created, "age_days": age_days})
    except Exception as e: return _err(e)


# --- 27. DNS params (aggregate) ---
@app.post("/api/2ip/dns-params")
async def t_dns_params(p: DomainBody):
    try:
        out = {}
        for t in ["A","AAAA","MX","NS","TXT","CAA","SOA"]:
            try:
                _, _, body, _, _ = await http_client.request(
                    "GET", f"https://dns.google/resolve?name={quote(p.domain)}&type={t}", timeout=8)
                d = json.loads(body.decode())
                out[t] = [a.get("data") for a in d.get("Answer",[])]
            except Exception: out[t] = []
        return _ok({"domain": p.domain, "records": out})
    except Exception as e: return _err(e)


# --- 28. Raw DNS check ---
@app.post("/api/2ip/dns-check")
async def t_dns_check(p: DomainBody):
    return await t_dns_params(p)


# --- 29. Password strength (uses existing password_strength) ---
@app.post("/api/2ip/password-strength")
async def t_pwd_strength(p: PasswordRequest):
    return {"status": STATUS_SUCCESS, "result": password_strength(p.password)}


# --- 30. SSL (existing ssl_certificate_sync) ---
@app.post("/api/2ip/ssl-check")
async def t_ssl_check(p: DomainBody):
    try:
        r = await asyncio.to_thread(ssl_certificate_sync, p.domain)
        return _ok(r)
    except Exception as e: return _err(e)


# ============================================================================
# FILE ANALYZER
# ============================================================================

@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = FastFile(...)):
    try:
        content = await file.read()
        size = len(content)
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        name = file.filename or "unknown"
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        text_exts = {"txt","log","json","csv","xml","html","htm","md","ini","cfg","conf","env","yml","yaml","py","js","ts","dart"}
        text_preview = ""
        if ext in text_exts:
            try:
                text_preview = content[:5000].decode("utf-8", errors="replace")
            except Exception:
                text_preview = ""
        return {
            "status": "SUCCESS",
            "result": {
                "filename": name,
                "size_bytes": size,
                "size_kb": round(size / 1024, 2),
                "extension": ext,
                "content_type": file.content_type,
                "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
                "text_preview": text_preview,
            },
        }
    except Exception as e:
        return {"status": "FAILED", "error": clamp_text(e)}


if __name__ == "__main__":
    import uvicorn

    print(f"{APP_NAME} {APP_VERSION}")
    print(f"Database: {DATABASE_PATH}")
    print(f"Self-check: {self_check()}")
    print(f"Tests: {run_local_tests()}")

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
