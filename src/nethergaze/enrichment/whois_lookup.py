"""Whois/RDAP enrichment with async thread pool and caching."""

from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from nethergaze.models import WhoisInfo
from nethergaze.utils import is_private_ip

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError

    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False

logger = logging.getLogger(__name__)




class WhoisLookupService:
    """Threaded whois/RDAP lookup service with TTL cache."""

    def __init__(
        self,
        max_workers: int = 3,
        cache_ttl: int = 86400,
        cache_dir: str | None = None,
    ):
        self._cache: dict[str, tuple[WhoisInfo, float]] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._cache_ttl = cache_ttl
        self._cache_dir = Path(cache_dir) if cache_dir else None
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="whois")
        # Unregister the atexit handler that waits for threads to finish,
        # so the process can exit even with pending whois lookups.
        import atexit
        import concurrent.futures.thread as _tmod
        atexit.unregister(_tmod._python_exit)

        if self._cache_dir:
            self._load_disk_cache()

    @property
    def available(self) -> bool:
        return HAS_IPWHOIS

    def lookup(
        self,
        ip: str,
        callback: Callable[[str, WhoisInfo], None] | None = None,
    ) -> WhoisInfo | None:
        """Request whois lookup for an IP. Returns cached result or None.

        If a callback is provided and no cached result exists, the lookup
        is performed in a background thread and callback is called with results.
        """
        if is_private_ip(ip):
            return WhoisInfo(network_name="Private", network_cidr="N/A")

        with self._lock:
            if ip in self._cache:
                info, ts = self._cache[ip]
                if time.time() - ts < self._cache_ttl:
                    return info
                # Expired — remove
                del self._cache[ip]

            if ip in self._pending:
                return None

            self._pending.add(ip)

        if not HAS_IPWHOIS:
            with self._lock:
                self._pending.discard(ip)
            return None

        self._executor.submit(self._do_lookup, ip, callback)
        return None

    def get_cached(self, ip: str) -> WhoisInfo | None:
        """Get cached whois info without triggering a lookup."""
        with self._lock:
            if ip in self._cache:
                info, ts = self._cache[ip]
                if time.time() - ts < self._cache_ttl:
                    return info
        return None

    def _do_lookup(
        self,
        ip: str,
        callback: Callable[[str, WhoisInfo], None] | None,
    ) -> None:
        """Perform RDAP lookup in background thread."""
        info = WhoisInfo()
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            info.network_name = result.get("network", {}).get("name", "?") or "?"
            cidr = result.get("network", {}).get("cidr", "?")
            info.network_cidr = cidr or "?"
            info.description = (
                result.get("network", {}).get("remarks", [{}])[0].get("description", "")
                if result.get("network", {}).get("remarks")
                else ""
            )
            # Try to extract abuse contact
            objects = result.get("objects", {})
            for obj_data in objects.values():
                contact = obj_data.get("contact", {})
                if contact.get("role") == "abuse" or "abuse" in obj_data.get("handle", "").lower():
                    for email_entry in contact.get("email", []):
                        if isinstance(email_entry, dict):
                            info.abuse_contact = email_entry.get("value", "")
                        else:
                            info.abuse_contact = str(email_entry)
                        if info.abuse_contact:
                            break
                if info.abuse_contact:
                    break
        except IPDefinedError:
            info.network_name = "Private/Reserved"
        except Exception as e:
            logger.debug("Whois lookup failed for %s: %s", ip, e)

        with self._lock:
            self._cache[ip] = (info, time.time())
            self._pending.discard(ip)

        self._save_to_disk(ip, info)

        if callback:
            try:
                callback(ip, info)
            except Exception:
                logger.debug("Whois callback failed for %s", ip, exc_info=True)

    def _load_disk_cache(self) -> None:
        """Load cached whois results from disk."""
        if not self._cache_dir:
            return
        cache_file = self._cache_dir / "whois_cache.json"
        if not cache_file.exists():
            return
        try:
            data = json.loads(cache_file.read_text())
            now = time.time()
            for ip, entry in data.items():
                ts = entry.get("_ts", 0)
                if now - ts < self._cache_ttl:
                    info = WhoisInfo(
                        network_name=entry.get("network_name", "?"),
                        network_cidr=entry.get("network_cidr", "?"),
                        description=entry.get("description", ""),
                        abuse_contact=entry.get("abuse_contact", ""),
                    )
                    self._cache[ip] = (info, ts)
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    def _save_to_disk(self, ip: str, info: WhoisInfo) -> None:
        """Persist a single whois result to disk cache."""
        if not self._cache_dir:
            return
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = self._cache_dir / "whois_cache.json"

        try:
            if cache_file.exists():
                data = json.loads(cache_file.read_text())
            else:
                data = {}
        except (json.JSONDecodeError, TypeError):
            data = {}

        data[ip] = {
            "network_name": info.network_name,
            "network_cidr": info.network_cidr,
            "description": info.description,
            "abuse_contact": info.abuse_contact,
            "_ts": time.time(),
        }
        cache_file.write_text(json.dumps(data, indent=2))

    def shutdown(self) -> None:
        """Shut down the thread pool."""
        self._executor.shutdown(wait=False, cancel_futures=True)
