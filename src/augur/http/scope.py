"""Scope guard. Refuses requests outside the allow-list and blocks the
common SSRF tricks (userinfo, IDN homographs, private/loopback/metadata IPs).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


class OutOfScope(Exception):
    """Raised when a request would target a host the user did not authorize."""


# default-deny private and loopback ranges, auto-lifts if the user scopes to one
_PRIVATE_DEFAULTS = True

_DEFAULT_PORTS = {"http": 80, "https": 443}
_HOST_RE = re.compile(r"^[a-z0-9.\-]+$")  # post-IDNA encoded host

_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})


@dataclass(frozen=True)
class ScopeGuard:
    allowed_origins: frozenset[str]
    deny_private: bool = _PRIVATE_DEFAULTS

    @classmethod
    def from_base_urls(cls, base_urls: list[str], deny_private: bool = _PRIVATE_DEFAULTS) -> ScopeGuard:
        origins = frozenset(_origin(u) for u in base_urls)
        if deny_private and any(_origin_is_private(o) for o in origins):
            deny_private = False
        return cls(origins, deny_private=deny_private)

    def check(self, url: str) -> None:
        origin = _origin(url)
        if origin not in self.allowed_origins:
            raise OutOfScope(
                f"refusing to send to {origin!r}, not in scope {sorted(self.allowed_origins)}"
            )
        host = urlparse(url).hostname or ""
        if self.deny_private:
            _check_not_private(host)
        else:
            _check_not_metadata(host)


def _check_not_metadata(host: str) -> None:
    try:
        ip = ipaddress.ip_address(_strip_brackets(host))
    except ValueError:
        return
    if str(ip) in _METADATA_IPS:
        raise OutOfScope(f"refusing cloud metadata ip: {ip}")


def _check_not_private(host: str) -> None:
    try:
        ip = ipaddress.ip_address(_strip_brackets(host))
    except ValueError:
        return
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
        or str(ip) in _METADATA_IPS
    ):
        raise OutOfScope(f"refusing private/metadata ip: {ip}")
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None and (
            mapped.is_loopback or mapped.is_link_local or mapped.is_private
            or mapped.is_unspecified or str(mapped) in _METADATA_IPS
        ):
            raise OutOfScope(f"refusing private/metadata ip (wrapped): {ip}")


def _strip_brackets(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _origin_is_private(origin: str) -> bool:
    p = urlparse(origin)
    host = _strip_brackets(p.hostname or "")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost",)
    return ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_unspecified


def _origin(url: str) -> str:
    if not isinstance(url, str) or not url:
        raise OutOfScope(f"invalid url: {url!r}")
    if url != url.strip():
        raise OutOfScope("refusing url with surrounding whitespace")
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise OutOfScope(f"refusing non-http scheme: {scheme!r}")
    if p.username is not None or p.password is not None:
        raise OutOfScope("refusing url with userinfo")
    host = p.hostname
    if not host:
        raise OutOfScope(f"invalid url, no host: {url!r}")
    if host.endswith("."):
        raise OutOfScope(f"refusing trailing-dot hostname: {host!r}")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if isinstance(ip, ipaddress.IPv6Address):
        host_canonical = f"[{ip.compressed}]"
    elif ip is not None:
        host_canonical = ip.compressed
    else:
        try:
            host_idna = host.encode("idna").decode("ascii").lower()
        except UnicodeError as e:
            raise OutOfScope(f"invalid host {host!r}: {e}")
        if not _HOST_RE.match(host_idna):
            raise OutOfScope(f"invalid host characters: {host_idna!r}")
        host_canonical = host_idna

    try:
        port = p.port if p.port is not None else _DEFAULT_PORTS[scheme]
    except ValueError as e:
        raise OutOfScope(f"invalid port in url: {e}")
    return f"{scheme}://{host_canonical}:{port}"
