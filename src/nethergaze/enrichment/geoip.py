"""GeoIP enrichment using MaxMind GeoLite2 databases."""

from __future__ import annotations

from pathlib import Path

from nethergaze.models import GeoInfo
from nethergaze.utils import is_private_ip

try:
    import geoip2.database
    import geoip2.errors

    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False


class GeoIPLookup:
    """MaxMind GeoLite2 lookup with in-memory caching."""

    def __init__(self, city_db: str, asn_db: str):
        self._city_reader = None
        self._asn_reader = None
        self._cache: dict[str, GeoInfo] = {}

        if not HAS_GEOIP2:
            return

        city_path = Path(city_db)
        asn_path = Path(asn_db)

        if city_path.exists():
            try:
                self._city_reader = geoip2.database.Reader(str(city_path))
            except Exception:
                pass

        if asn_path.exists():
            try:
                self._asn_reader = geoip2.database.Reader(str(asn_path))
            except Exception:
                pass

    @property
    def available(self) -> bool:
        """Whether at least one database is loaded."""
        return self._city_reader is not None or self._asn_reader is not None

    def lookup(self, ip: str) -> GeoInfo:
        """Look up GeoIP info for an IP address. Returns default GeoInfo on failure."""
        if ip in self._cache:
            return self._cache[ip]

        if is_private_ip(ip):
            info = GeoInfo(country_code="--", country_name="Private", city="LAN")
            self._cache[ip] = info
            return info

        info = GeoInfo()

        if self._city_reader:
            try:
                resp = self._city_reader.city(ip)
                info.country_code = resp.country.iso_code or "?"
                info.country_name = resp.country.name or "Unknown"
                info.city = resp.city.name or "?"
                if resp.location:
                    info.latitude = resp.location.latitude or 0.0
                    info.longitude = resp.location.longitude or 0.0
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass

        if self._asn_reader:
            try:
                resp = self._asn_reader.asn(ip)
                info.asn = resp.autonomous_system_number
                info.as_org = resp.autonomous_system_organization or "?"
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass

        self._cache[ip] = info
        return info

    def close(self) -> None:
        """Close database readers."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
