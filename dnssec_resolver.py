#!/usr/bin/env python3
"""Iterative DNS resolver with local, top-down DNSSEC validation.

Concept (unchanged): start at the root servers, follow delegations downward,
and authenticate every zone cut from a local root trust anchor
(root DNSKEY -> DS -> child DNSKEY -> ... -> answer RRSIG).

Requirements: Python >= 3.10, dnspython >= 2.4, cryptography.

Scope and known limitations:
  * IPv4 transport only (as in the original).
  * DNAME synthesis is not supported.
  * Results are not cached across ``resolve()`` calls (root keys excepted).
  * Wildcard NODATA proofs and some empty-non-terminal NSEC3 proofs that do not
    fit the RFC 4035 / RFC 5155 patterns implemented here are rejected
    as bogus rather than guessed at.

CLI exit codes: 0 answered, 1 resolution failure, 2 usage error,
3 NXDOMAIN, 4 DNSSEC failure (bogus or required-but-insecure).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import logging
import os
import random
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Sequence, TypeVar

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

log = logging.getLogger("dnssec_resolver")

T = TypeVar("T")

# =========================================================
# CONSTANTS
# =========================================================

ROOT_SERVERS: tuple[str, ...] = (
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
)

# IANA root trust anchors (https://data.iana.org/root-anchors/root-anchors.xml).
# KSK-2017 (20326) and KSK-2024 (38696). KSK-2024 begins signing on 2026-10-11;
# a resolver without it fails validation after that date.
DEFAULT_ROOT_DS: tuple[str, ...] = (
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
)

IN = dns.rdataclass.IN
ROOT = dns.name.root

DNSKEY_ZONE_FLAG = 0x0100
DNSKEY_REVOKE_FLAG = 0x0080
NSEC3_OPTOUT_FLAG = 0x01

SUPPORTED_ALGORITHMS = frozenset({5, 7, 8, 10, 13, 14, 15, 16})
SUPPORTED_DS_DIGESTS = frozenset({1, 2, 4})

_RT = dns.rdatatype


# =========================================================
# EXCEPTIONS
# =========================================================

class ResolverError(Exception):
    """Base class for all resolver failures."""


class ConfigError(ResolverError):
    """Invalid configuration or trust anchor material."""


class ResolutionError(ResolverError):
    """Name could not be resolved (network, lame servers, limits)."""


class ValidationError(ResolverError):
    """DNSSEC validation failed (bogus data)."""


class _Retry(Exception):
    """Internal: this server's response is unusable, try the next one."""


class _InsecureProof(Exception):
    """Internal: denial proof uses parameters that make it insecure (RFC 9276)."""


# =========================================================
# CONFIGURATION AND RESULT TYPES
# =========================================================

@dataclass(frozen=True)
class ResolverConfig:
    root_servers: tuple[str, ...] = ROOT_SERVERS
    port: int = 53
    timeout: float = 3.0
    retries: int = 1                 # extra UDP attempts per server on timeout
    max_referrals: int = 30
    max_cname_chain: int = 16
    max_ns_depth: int = 4            # nested glueless nameserver lookups
    max_queries: int = 200           # total network queries per resolve()
    edns_payload: int = 1232
    max_nsec3_iterations: int = 150
    trust_anchor_path: Optional[str] = None
    validate: bool = True
    require_dnssec: bool = False
    allow_private_servers: bool = False

    def __post_init__(self) -> None:
        if not self.root_servers:
            raise ConfigError("root_servers must not be empty")
        if self.timeout <= 0 or self.retries < 0:
            raise ConfigError("timeout must be > 0 and retries >= 0")
        if not 1 <= self.port <= 65535:
            raise ConfigError("invalid port")
        if min(self.max_referrals, self.max_cname_chain, self.max_queries) < 1:
            raise ConfigError("limits must be >= 1")
        if self.require_dnssec and not self.validate:
            raise ConfigError("require_dnssec needs validate=True")


class Security(Enum):
    SECURE = "secure"
    INSECURE = "insecure"
    NOT_VALIDATED = "not-validated"


@dataclass(frozen=True)
class Result:
    qname: dns.name.Name
    qtype: int
    rcode: int
    security: Security
    answers: tuple[dns.rrset.RRset, ...]
    cnames: tuple[dns.rrset.RRset, ...]
    server: str

    @property
    def nxdomain(self) -> bool:
        return self.rcode == dns.rcode.NXDOMAIN

    @property
    def nodata(self) -> bool:
        return self.rcode == dns.rcode.NOERROR and not self.answers

    def format(self) -> str:
        lines = [
            f"{self.qname} {_RT.to_text(self.qtype)} -> "
            f"{dns.rcode.to_text(self.rcode)} [{self.security.value}] via {self.server}"
        ]
        for rr in self.cnames:
            lines.append(f"  CNAME {rr.name} -> {rr[0].target}")
        for rr in self.answers:
            for rd in rr:
                lines.append(f"  {rr.name} {rr.ttl} {_RT.to_text(rr.rdtype)} {rd.to_text()}")
        return "\n".join(lines)


# =========================================================
# TRUST ANCHORS
# =========================================================

@dataclass(frozen=True)
class TrustAnchors:
    ds: tuple = ()
    dnskeys: tuple = ()

    def __bool__(self) -> bool:
        return bool(self.ds or self.dnskeys)


def load_trust_anchors(path: Optional[str] = None) -> TrustAnchors:
    """Load root trust anchors (DS and/or DNSKEY lines, zone-file syntax).

    Without ``path``, ``root.key`` next to this module is used; if absent the
    built-in IANA DS set is used. An explicit but missing path is an error.
    """
    explicit = path is not None
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "root.key")

    if not os.path.isfile(path):
        if explicit:
            raise ConfigError(f"trust anchor file not found: {path}")
        log.warning("%s not found; using built-in IANA root DS records", path)
        return TrustAnchors(
            ds=tuple(dns.rdata.from_text(IN, "DS", text) for text in DEFAULT_ROOT_DS)
        )

    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read trust anchor file {path}: {exc}") from exc

    ds_records, dnskeys = [], []
    for lineno, raw in enumerate(lines, 1):
        tokens = raw.split(";", 1)[0].split()
        if len(tokens) < 5 or tokens[0] != ".":
            continue
        upper = [t.upper() for t in tokens]
        idx = next(
            (i for i in range(1, min(4, len(tokens))) if upper[i] in ("DS", "DNSKEY")),
            None,
        )
        if idx is None:
            continue
        try:
            rdata = dns.rdata.from_text(IN, upper[idx], " ".join(tokens[idx + 1:]))
        except (dns.exception.DNSException, ValueError) as exc:
            raise ConfigError(f"{path}:{lineno}: invalid {upper[idx]} record: {exc}") from exc
        (ds_records if upper[idx] == "DS" else dnskeys).append(rdata)

    anchors = TrustAnchors(ds=tuple(ds_records), dnskeys=tuple(dnskeys))
    if not anchors:
        raise ConfigError(f"no DS or DNSKEY trust anchors found in {path}")
    log.info("loaded %d DS and %d DNSKEY trust anchor(s)", len(ds_records), len(dnskeys))
    return anchors


# =========================================================
# GENERIC HELPERS
# =========================================================

def _parse_name(domain: str) -> dns.name.Name:
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")
    try:
        return dns.name.from_text(domain.strip())
    except dns.exception.DNSException as exc:
        raise ValueError(f"invalid domain name {domain!r}: {exc}") from exc


def _parse_type(qtype) -> int:
    try:
        rdtype = qtype if isinstance(qtype, int) else _RT.from_text(str(qtype).upper())
    except dns.exception.DNSException as exc:
        raise ValueError(f"unknown record type {qtype!r}") from exc
    if _RT.is_metatype(rdtype):
        raise ValueError(f"meta type {_RT.to_text(rdtype)} cannot be resolved")
    return rdtype


def _find(section, name: dns.name.Name, rdtype: int) -> Optional[dns.rrset.RRset]:
    for rr in section:
        if rr.rdtype == rdtype and rr.rdclass == IN and rr.name == name:
            return rr
    return None


def _rrsigs_for(resp: dns.message.Message, rr: dns.rrset.RRset) -> list:
    sigs = []
    for section in (resp.answer, resp.authority):
        for cand in section:
            if cand.rdtype == _RT.RRSIG and cand.name == rr.name and cand.covers == rr.rdtype:
                sigs.extend(cand)
    return sigs


def _make_rrset(name, rdtype: int, ttl: int, rdatas, covers: int = 0) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, IN, rdtype, covers)
    rrset.update_ttl(ttl)
    for rdata in rdatas:
        rrset.add(rdata)
    return rrset


def _owner_label_count(name: dns.name.Name) -> int:
    count = len(name.labels) - 1  # exclude root
    if count and name.labels[0] == b"*":
        count -= 1
    return count


def _wildcard_of(ce: dns.name.Name) -> dns.name.Name:
    return dns.name.Name((b"*",) + ce.labels)


def _name_between(lo: dns.name.Name, hi: dns.name.Name, x: dns.name.Name) -> bool:
    """True if x lies strictly inside the canonical-order interval (lo, hi)."""
    lo, hi, x = lo.canonicalize(), hi.canonicalize(), x.canonicalize()
    if lo < hi:
        return lo < x < hi
    return x > lo or x < hi  # wrap-around (last record in zone)


def _has_type(rdata, rdtype: int) -> bool:
    window, offset = rdtype >> 8, rdtype & 0xFF
    for win, bitmap in rdata.windows:
        if win == window:
            idx = offset // 8
            return idx < len(bitmap) and bool(bitmap[idx] & (0x80 >> (offset % 8)))
    return False


def _usable_key(key) -> bool:
    return (
        key.protocol == 3
        and bool(key.flags & DNSKEY_ZONE_FLAG)
        and not key.flags & DNSKEY_REVOKE_FLAG
    )


def _ds_matches(zone: dns.name.Name, key, ds) -> bool:
    try:
        if ds.key_tag != dns.dnssec.key_id(key) or ds.algorithm != key.algorithm:
            return False
        computed = dns.dnssec.make_ds(zone, key, dns.dnssec.DSDigest(ds.digest_type))
    except (dns.exception.DNSException, ValueError):
        return False
    return computed.digest == ds.digest


def _validate_sigs(rrset, sigs: Sequence, keys: dict) -> None:
    sigset = _make_rrset(rrset.name, _RT.RRSIG, rrset.ttl, sigs, covers=rrset.rdtype)
    try:
        dns.dnssec.validate(rrset, sigset, keys)
    except (dns.exception.DNSException, ValueError, TypeError) as exc:
        raise ValidationError(
            f"{rrset.name} {_RT.to_text(rrset.rdtype)}: signature check failed: {exc}"
        ) from exc


# =========================================================
# AUTHENTICATED DENIAL OF EXISTENCE (NSEC / NSEC3)
# =========================================================

@dataclass
class _N3:
    owner_hash: bytes
    next_hash: bytes
    rdata: object


class _Denial:
    """Evaluates already-signature-verified NSEC/NSEC3 records of one zone."""

    def __init__(self, zone: dns.name.Name, nsec_sets, nsec3_sets, max_iterations: int):
        self.zone = zone
        self.nsec = [(rr.name, rr[0]) for rr in nsec_sets]
        self.n3: list[_N3] = []
        self._hashes: dict = {}
        for rr in nsec3_sets:
            if len(rr.name.labels) < 2 or rr.name.parent() != zone:
                continue
            try:
                owner_hash = base64.b32hexdecode(rr.name.labels[0].decode("ascii").upper())
            except ValueError:
                continue
            for rd in rr:
                if rd.algorithm != 1 or rd.iterations > max_iterations:
                    raise _InsecureProof()
                self.n3.append(_N3(owner_hash, rd.next, rd))

    # ---- NSEC ----

    def nsec_for(self, name):
        for owner, rd in self.nsec:
            if owner == name:
                return rd
        return None

    def nsec_cover(self, name):
        for owner, rd in self.nsec:
            if _name_between(owner, rd.next, name):
                return owner, rd
        return None

    def _nsec_closest_encloser(self, qname, cover) -> dns.name.Name:
        owner, rd = cover
        best = ROOT
        for other in (owner, rd.next):
            common = qname.fullcompare(other)[2]
            cand = qname.split(common)[1]
            if len(cand.labels) > len(best.labels):
                best = cand
        return best

    # ---- NSEC3 ----

    def _hash(self, name, rd) -> bytes:
        key = (name, rd.salt, rd.iterations)
        cached = self._hashes.get(key)
        if cached is None:
            digest = hashlib.sha1(name.canonicalize().to_wire() + rd.salt).digest()
            for _ in range(rd.iterations):
                digest = hashlib.sha1(digest + rd.salt).digest()
            self._hashes[key] = cached = digest
        return cached

    def n3_match(self, name) -> Optional[_N3]:
        for entry in self.n3:
            if self._hash(name, entry.rdata) == entry.owner_hash:
                return entry
        return None

    def n3_cover(self, name) -> Optional[_N3]:
        for entry in self.n3:
            h = self._hash(name, entry.rdata)
            lo, hi = entry.owner_hash, entry.next_hash
            if (lo < h < hi) if lo < hi else (h > lo or h < hi):
                return entry
        return None

    def n3_closest_encloser(self, qname):
        nc, ce = qname, qname.parent() if qname != ROOT else ROOT
        while True:
            if self.n3_match(ce):
                cover = self.n3_cover(nc)
                return (ce, nc, cover) if cover else None
            if ce == self.zone or not ce.is_subdomain(self.zone) or ce == ROOT:
                return None
            nc, ce = ce, ce.parent()

    # ---- proofs ----

    @staticmethod
    def _lacks(rd, qtype: int) -> bool:
        return not _has_type(rd, qtype) and not _has_type(rd, _RT.CNAME)

    def proves_nxdomain(self, qname) -> bool:
        if self.nsec:
            cover = self.nsec_cover(qname)
            if cover is None:
                return False
            wildcard = _wildcard_of(self._nsec_closest_encloser(qname, cover))
            return self.nsec_for(wildcard) is None and self.nsec_cover(wildcard) is not None
        proof = self.n3_closest_encloser(qname)
        if proof is None:
            return False
        wildcard = _wildcard_of(proof[0])
        return self.n3_match(wildcard) is None and self.n3_cover(wildcard) is not None

    def proves_nodata(self, qname, qtype: int) -> bool:
        if self.nsec:
            rd = self.nsec_for(qname)
            if rd is not None:
                return self._lacks(rd, qtype)
            cover = self.nsec_cover(qname)
            if cover is None:
                return False
            if cover[1].next.is_subdomain(qname):  # empty non-terminal
                return True
            wild = self.nsec_for(_wildcard_of(self._nsec_closest_encloser(qname, cover)))
            return wild is not None and self._lacks(wild, qtype)
        entry = self.n3_match(qname)
        if entry is not None:
            return self._lacks(entry.rdata, qtype)
        proof = self.n3_closest_encloser(qname)
        if proof is None:
            return False
        wild = self.n3_match(_wildcard_of(proof[0]))
        if wild is not None and self._lacks(wild.rdata, qtype):
            return True
        return qtype == _RT.DS and bool(proof[2].rdata.flags & NSEC3_OPTOUT_FLAG)

    def proves_no_ds(self, child) -> bool:
        if self.nsec:
            rd = self.nsec_for(child)
            return (
                rd is not None
                and _has_type(rd, _RT.NS)
                and not _has_type(rd, _RT.DS)
                and not _has_type(rd, _RT.SOA)
            )
        entry = self.n3_match(child)
        if entry is not None:
            rd = entry.rdata
            return (
                _has_type(rd, _RT.NS)
                and not _has_type(rd, _RT.DS)
                and not _has_type(rd, _RT.SOA)
            )
        proof = self.n3_closest_encloser(child)
        return proof is not None and bool(proof[2].rdata.flags & NSEC3_OPTOUT_FLAG)


# =========================================================
# RESOLUTION STATE
# =========================================================

@dataclass
class _Zone:
    name: dns.name.Name
    servers: list
    keys: Optional[dns.rrset.RRset]  # authenticated DNSKEYs; None => insecure

    @property
    def secure(self) -> bool:
        return self.keys is not None


@dataclass
class _Referral:
    child: dns.name.Name
    ns_names: list
    glue: list
    ds: Optional[list]  # None => child is insecure (or parent already insecure)


@dataclass
class _Final:
    rcode: int
    answers: list
    chain: list
    secure: bool
    redirect: Optional[dns.name.Name]
    server: str


@dataclass
class _Context:
    max_queries: int
    queries: int = 0
    cname_hops: int = 0
    zones: dict = field(default_factory=dict)
    active: set = field(default_factory=set)

    def spend(self) -> None:
        self.queries += 1
        if self.queries > self.max_queries:
            raise ResolutionError(f"query budget of {self.max_queries} exhausted")


# =========================================================
# RESOLVER
# =========================================================

class Resolver:
    def __init__(
        self,
        config: Optional[ResolverConfig] = None,
        trust_anchors: Optional[TrustAnchors] = None,
    ) -> None:
        self.cfg = config or ResolverConfig()
        self._rng = random.SystemRandom()
        self._root_servers = [s for s in self.cfg.root_servers if self._address_allowed(s)]
        if not self._root_servers:
            raise ConfigError("no usable root server addresses")
        self.anchors = TrustAnchors()
        if self.cfg.validate:
            self.anchors = (
                trust_anchors
                if trust_anchors is not None
                else load_trust_anchors(self.cfg.trust_anchor_path)
            )
            if not self.anchors:
                raise ConfigError("validation enabled but no trust anchors available")
        self._root_cache: Optional[tuple[float, _Zone]] = None

    # ---------------- public API ----------------

    def resolve(self, domain: str, qtype="A") -> Result:
        qname = _parse_name(domain)
        rdtype = _parse_type(qtype)
        ctx = _Context(self.cfg.max_queries)
        result = self._resolve(qname, rdtype, ctx, self.cfg.validate, 0)
        if self.cfg.require_dnssec and result.security is not Security.SECURE:
            raise ValidationError(f"{qname} could not be validated (zone is insecure)")
        return result

    # ---------------- resolution loop ----------------

    def _resolve(self, qname, rdtype, ctx: _Context, validate: bool, depth: int) -> Result:
        key = (qname, rdtype, validate)
        if key in ctx.active:
            raise ResolutionError(f"circular dependency while resolving {qname}")
        ctx.active.add(key)
        try:
            cnames: list = []
            secure = validate
            current, seen = qname, {qname}
            while True:
                step = self._iterate(current, rdtype, ctx, validate, depth)
                cnames.extend(step.chain)
                secure = secure and step.secure
                if step.redirect is None:
                    break
                ctx.cname_hops += len(step.chain)
                if ctx.cname_hops > self.cfg.max_cname_chain:
                    raise ResolutionError("CNAME chain too long")
                if step.redirect in seen:
                    raise ResolutionError(f"CNAME loop at {step.redirect}")
                seen.add(step.redirect)
                log.debug("following CNAME to %s", step.redirect)
                current = step.redirect
        finally:
            ctx.active.discard(key)

        if not validate:
            security = Security.NOT_VALIDATED
        else:
            security = Security.SECURE if secure else Security.INSECURE
        return Result(
            qname=qname,
            qtype=rdtype,
            rcode=step.rcode,
            security=security,
            answers=tuple(step.answers),
            cnames=tuple(cnames),
            server=step.server,
        )

    def _iterate(self, qname, qtype, ctx: _Context, validate: bool, depth: int) -> _Final:
        zone = self._start_zone(qname, ctx, validate)
        for _ in range(self.cfg.max_referrals):
            log.debug("asking zone %s for %s %s", zone.name, qname, _RT.to_text(qtype))
            step = self._ask(
                zone.servers,
                qname,
                qtype,
                ctx,
                lambda resp, srv, z=zone: self._evaluate(resp, srv, z, qname, qtype, ctx),
            )
            if isinstance(step, _Final):
                return step
            zone = self._descend(zone, step, ctx, validate, depth)
        raise ResolutionError(f"too many referrals resolving {qname}")

    # ---------------- zone setup ----------------

    def _start_zone(self, qname, ctx: _Context, validate: bool) -> _Zone:
        if not validate:
            return _Zone(ROOT, list(self._root_servers), None)
        best: Optional[_Zone] = None
        for zname, zone in ctx.zones.items():
            if qname.is_subdomain(zname) and (
                best is None or len(zname.labels) > len(best.name.labels)
            ):
                best = zone
        return best or self._root_zone(ctx)

    def _root_zone(self, ctx: _Context) -> _Zone:
        now = time.monotonic()
        cached = self._root_cache
        if cached is not None and cached[0] > now:
            return cached[1]
        keys = self._fetch_dnskeys(
            ROOT,
            self._root_servers,
            ctx,
            ds_list=self.anchors.ds,
            anchor_keys=self.anchors.dnskeys,
        )
        zone = _Zone(ROOT, list(self._root_servers), keys)
        self._root_cache = (now + min(keys.ttl, 3600), zone)
        log.debug("root DNSKEY set authenticated against trust anchor")
        return zone

    def _descend(self, parent: _Zone, ref: _Referral, ctx: _Context, validate: bool, depth: int) -> _Zone:
        servers = ref.glue or self._resolve_ns_addresses(ref.ns_names, ctx, depth)
        if not servers:
            raise ResolutionError(f"no reachable nameserver addresses for {ref.child}")
        if validate and parent.secure and ref.ds is not None:
            child = self._build_zone(ref.child, servers, ref.ds, ctx)
        else:
            child = _Zone(ref.child, servers, None)
            if validate:
                log.info("delegation to %s is insecure", ref.child)
        if validate:
            ctx.zones[ref.child] = child
        return child

    def _build_zone(self, name, servers, ds_list, ctx: _Context) -> _Zone:
        keys = self._fetch_dnskeys(name, servers, ctx, ds_list=ds_list)
        log.debug("zone %s authenticated", name)
        return _Zone(name, list(servers), keys)

    def _zone_for_name(self, zone: _Zone, target, ctx: _Context) -> _Zone:
        """Zone state for ``target`` (apex of a zone served by the same servers)."""
        if target == zone.name:
            return zone
        if not target.is_subdomain(zone.name):
            raise ValidationError(f"{target} is outside zone {zone.name}")
        cached = ctx.zones.get(target)
        if cached is None:
            resp = self._ask(zone.servers, target, _RT.DS, ctx, self._accept_noerror)
            ds_list = self._validate_delegation(zone, target, resp)
            if ds_list is None:
                raise ValidationError(f"signature by {target} but no secure delegation")
            cached = self._build_zone(target, zone.servers, ds_list, ctx)
            ctx.zones[target] = cached
        if not cached.secure:
            raise ValidationError(f"{target} is an insecure zone")
        return cached

    def _resolve_ns_addresses(self, ns_names, ctx: _Context, depth: int) -> list:
        if depth >= self.cfg.max_ns_depth:
            raise ResolutionError("nameserver lookup nesting too deep")
        names = list(ns_names)
        self._rng.shuffle(names)
        addresses: list = []
        for ns in names[:4]:
            try:
                res = self._resolve(ns, _RT.A, ctx, False, depth + 1)
            except ResolverError as exc:
                log.debug("could not resolve nameserver %s: %s", ns, exc)
                continue
            for rr in res.answers:
                addresses.extend(rd.address for rd in rr if self._address_allowed(rd.address))
            if len(addresses) >= 2:
                break
        return list(dict.fromkeys(addresses))

    # ---------------- network ----------------

    def _address_allowed(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if ip.version != 4:
            return False
        if self.cfg.allow_private_servers:
            return not (ip.is_unspecified or ip.is_multicast)
        return ip.is_global

    def _transact(self, server: str, qname, qtype: int) -> dns.message.Message:
        query = dns.message.make_query(
            qname,
            qtype,
            use_edns=0,
            want_dnssec=True,
            payload=self.cfg.edns_payload,
            flags=0,
        )
        last: Exception = dns.exception.Timeout()
        for _ in range(self.cfg.retries + 1):
            try:
                resp, _used_tcp = dns.query.udp_with_fallback(
                    query,
                    server,
                    timeout=self.cfg.timeout,
                    port=self.cfg.port,
                    ignore_unexpected=True,
                )
            except dns.exception.Timeout as exc:
                last = exc
                continue
            if not query.is_response(resp):
                raise dns.exception.FormError("response does not match query")
            return resp
        raise last

    def _ask(self, servers, qname, qtype: int, ctx: _Context, handler: Callable[[dns.message.Message, str], T]) -> T:
        order = list(servers)
        self._rng.shuffle(order)
        net_error: Optional[Exception] = None
        soft_error: Optional[Exception] = None
        validation_error: Optional[ValidationError] = None
        for server in order:
            ctx.spend()
            try:
                resp = self._transact(server, qname, qtype)
            except (dns.exception.DNSException, OSError, EOFError) as exc:
                log.debug("%s: %s", server, exc)
                net_error = exc
                continue
            try:
                return handler(resp, server)
            except _Retry as exc:
                log.debug("%s: %s", server, exc)
                soft_error = exc
            except ValidationError as exc:
                log.warning("%s: %s", server, exc)
                validation_error = exc
        if validation_error is not None:
            raise validation_error
        raise ResolutionError(
            f"no usable response for {qname} {_RT.to_text(qtype)} from "
            f"{len(order)} server(s): {soft_error or net_error}"
        )

    @staticmethod
    def _accept_noerror(resp: dns.message.Message, server: str) -> dns.message.Message:
        if resp.rcode() != dns.rcode.NOERROR:
            raise _Retry(f"{server} returned {dns.rcode.to_text(resp.rcode())}")
        return resp

    # ---------------- response classification ----------------

    def _evaluate(self, resp, server, zone: _Zone, qname, qtype, ctx: _Context):
        rcode = resp.rcode()
        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            raise _Retry(f"{server} returned {dns.rcode.to_text(rcode)}")
        secure = zone.secure
        authoritative = bool(resp.flags & dns.flags.AA)

        cnames, final, redirect = self._follow_answer(resp, qname, qtype)
        if cnames or final is not None:
            if not secure and not authoritative:
                raise _Retry(f"{server} gave a non-authoritative answer")
            if secure:
                for rr in cnames + ([final] if final is not None else []):
                    self._validate_answer_rrset(rr, resp, zone, ctx)
            return _Final(
                dns.rcode.NOERROR,
                [final] if final is not None else [],
                cnames,
                secure,
                redirect,
                server,
            )

        has_soa = any(rr.rdtype == _RT.SOA for rr in resp.authority)
        if rcode == dns.rcode.NOERROR and not has_soa:
            ns_rrset = self._find_referral(resp, zone, qname)
            if ns_rrset is not None:
                return self._build_referral(resp, ns_rrset, zone)

        if not authoritative:
            raise _Retry(f"{server} gave a non-authoritative negative response")
        nxdomain = rcode == dns.rcode.NXDOMAIN
        if secure:
            secure = self._validate_negative(resp, zone, qname, qtype, nxdomain, ctx)
        return _Final(rcode, [], [], secure, None, server)

    @staticmethod
    def _follow_answer(resp, qname, qtype: int):
        cnames: list = []
        name, seen = qname, {qname}
        while True:
            rr = _find(resp.answer, name, qtype)
            if rr is not None:
                return cnames, rr, None
            if qtype == _RT.CNAME:
                break
            cn = _find(resp.answer, name, _RT.CNAME)
            if cn is None:
                break
            if len(cn) != 1:
                raise _Retry("RRset with multiple CNAME records")
            cnames.append(cn)
            name = cn[0].target
            if name in seen:
                raise ResolutionError(f"CNAME loop at {name}")
            seen.add(name)
        return cnames, None, (name if cnames else None)

    @staticmethod
    def _find_referral(resp, zone: _Zone, qname) -> Optional[dns.rrset.RRset]:
        for rr in resp.authority:
            if rr.rdtype != _RT.NS or rr.rdclass != IN:
                continue
            if rr.name == zone.name or not rr.name.is_subdomain(zone.name):
                continue  # upward/sideways or same-zone referral: lame
            if not qname.is_subdomain(rr.name):
                continue
            return rr
        return None

    def _build_referral(self, resp, ns_rrset, zone: _Zone) -> _Referral:
        ns_names = [rd.target for rd in ns_rrset]
        wanted = set(ns_names)
        glue: list = []
        for rr in resp.additional:
            if rr.rdtype != _RT.A or rr.name not in wanted or not rr.name.is_subdomain(zone.name):
                continue  # bailiwick check on glue
            glue.extend(rd.address for rd in rr if self._address_allowed(rd.address))
        ds_list = self._validate_delegation(zone, ns_rrset.name, resp) if zone.secure else None
        return _Referral(ns_rrset.name, ns_names, list(dict.fromkeys(glue)), ds_list)

    # ---------------- DNSSEC ----------------

    def _verify(self, rrset, resp, zone: _Zone) -> list:
        """Verify ``rrset`` against ``zone``'s keys. Returns the RRSIGs that were considered."""
        if not zone.secure:
            raise ValidationError(f"zone {zone.name} has no authenticated keys")
        sigs = [s for s in _rrsigs_for(resp, rrset) if s.signer == zone.name]
        if not sigs:
            raise ValidationError(
                f"no RRSIG by {zone.name} over {rrset.name} {_RT.to_text(rrset.rdtype)}"
            )
        _validate_sigs(rrset, sigs, {zone.name: zone.keys})
        return sigs

    def _validate_answer_rrset(self, rrset, resp, zone: _Zone, ctx: _Context) -> None:
        all_sigs = _rrsigs_for(resp, rrset)
        if not all_sigs:
            raise ValidationError(
                f"unsigned {rrset.name} {_RT.to_text(rrset.rdtype)} in secure zone {zone.name}"
            )
        signers = {s.signer for s in all_sigs}
        if zone.name in signers:
            signer_zone = zone
        else:
            candidates = [
                s for s in signers if s.is_subdomain(zone.name) and rrset.name.is_subdomain(s)
            ]
            if not candidates:
                raise ValidationError(
                    f"{rrset.name}: no RRSIG signer within zone {zone.name}"
                )
            signer_zone = self._zone_for_name(zone, max(candidates, key=lambda n: len(n.labels)), ctx)

        used = self._verify(rrset, resp, signer_zone)
        owner_labels = _owner_label_count(rrset.name)
        if any(sig.labels < owner_labels for sig in used):
            self._check_wildcard_expansion(rrset, used, resp, signer_zone)

    def _check_wildcard_expansion(self, rrset, sigs, resp, zone: _Zone) -> None:
        """RFC 4035 5.3.4: a wildcard answer needs proof that no closer match exists."""
        nsec_sets, nsec3_sets = self._verified_denial_sets(resp, zone)
        try:
            denial = _Denial(zone.name, nsec_sets, nsec3_sets, self.cfg.max_nsec3_iterations)
        except _InsecureProof:
            return
        for sig in sigs:
            if sig.labels >= _owner_label_count(rrset.name):
                continue
            next_closer = rrset.name.split(sig.labels + 2)[1]
            covered = (
                denial.nsec_cover(next_closer) is not None
                if denial.nsec
                else denial.n3_cover(next_closer) is not None
            )
            if covered:
                return
        raise ValidationError(f"{rrset.name}: wildcard expansion lacks non-existence proof")

    def _verified_denial_sets(self, resp, zone: _Zone):
        nsec_sets, nsec3_sets = [], []
        for rr in resp.authority:
            if rr.rdtype == _RT.NSEC:
                self._verify(rr, resp, zone)
                nsec_sets.append(rr)
            elif rr.rdtype == _RT.NSEC3:
                self._verify(rr, resp, zone)
                nsec3_sets.append(rr)
        return nsec_sets, nsec3_sets

    def _validate_negative(self, resp, zone: _Zone, qname, qtype: int, nxdomain: bool, ctx: _Context) -> bool:
        """Authenticate NXDOMAIN/NODATA. Returns False if the proof is merely insecure."""
        soa = next((rr for rr in resp.authority if rr.rdtype == _RT.SOA), None)
        if soa is None:
            raise ValidationError(f"negative response for {qname} lacks SOA")
        if not (qname.is_subdomain(soa.name) and soa.name.is_subdomain(zone.name)):
            raise ValidationError(f"SOA {soa.name} is out of bailiwick for {qname}")
        nzone = self._zone_for_name(zone, soa.name, ctx)
        self._verify(soa, resp, nzone)
        nsec_sets, nsec3_sets = self._verified_denial_sets(resp, nzone)
        if not nsec_sets and not nsec3_sets:
            raise ValidationError(f"negative response for {qname} lacks NSEC/NSEC3 proof")
        try:
            denial = _Denial(nzone.name, nsec_sets, nsec3_sets, self.cfg.max_nsec3_iterations)
            proven = denial.proves_nxdomain(qname) if nxdomain else denial.proves_nodata(qname, qtype)
        except _InsecureProof:
            log.info("NSEC3 parameters exceed policy; treating %s as insecure", qname)
            return False
        if not proven:
            kind = "NXDOMAIN" if nxdomain else "NODATA"
            raise ValidationError(f"{kind} for {qname} is not proven by the NSEC/NSEC3 records")
        return True

    def _validate_delegation(self, parent: _Zone, child, resp) -> Optional[list]:
        """Authenticate the DS (or absence of DS) for ``child`` using ``parent`` keys.

        Returns usable DS records, or None when the delegation is provably insecure.
        """
        ds_rrset = _find(resp.answer, child, _RT.DS) or _find(resp.authority, child, _RT.DS)
        if ds_rrset is not None:
            self._verify(ds_rrset, resp, parent)
            usable = [
                ds for ds in ds_rrset
                if ds.digest_type in SUPPORTED_DS_DIGESTS and ds.algorithm in SUPPORTED_ALGORITHMS
            ]
            if not usable:
                log.info("no supported DS algorithm/digest for %s; treating as insecure", child)
                return None
            return usable

        nsec_sets, nsec3_sets = self._verified_denial_sets(resp, parent)
        try:
            denial = _Denial(parent.name, nsec_sets, nsec3_sets, self.cfg.max_nsec3_iterations)
        except _InsecureProof:
            return None
        if (nsec_sets or nsec3_sets) and denial.proves_no_ds(child):
            return None
        raise ValidationError(f"{child}: DS missing and no valid proof of insecure delegation")

    def _fetch_dnskeys(self, zone_name, servers, ctx: _Context, ds_list=(), anchor_keys=()) -> dns.rrset.RRset:
        def handler(resp, server):
            rrset = _find(resp.answer, zone_name, _RT.DNSKEY)
            if rrset is None:
                raise _Retry(f"{server} returned no DNSKEY RRset for {zone_name}")
            return self._authenticate_dnskeys(zone_name, rrset, resp, ds_list, anchor_keys)

        return self._ask(servers, zone_name, _RT.DNSKEY, ctx, handler)

    def _authenticate_dnskeys(self, zone_name, rrset, resp, ds_list, anchor_keys) -> dns.rrset.RRset:
        sigs = [s for s in _rrsigs_for(resp, rrset) if s.signer == zone_name]
        if not sigs:
            raise ValidationError(f"DNSKEY RRset of {zone_name} is unsigned")
        entry_points = [
            key for key in rrset
            if _usable_key(key)
            and (key in anchor_keys or any(_ds_matches(zone_name, key, ds) for ds in ds_list))
        ]
        if not entry_points:
            raise ValidationError(f"no DNSKEY of {zone_name} matches the DS/trust anchor")
        failure: Optional[ValidationError] = None
        for key in entry_points:
            single = _make_rrset(zone_name, _RT.DNSKEY, rrset.ttl, [key])
            try:
                _validate_sigs(rrset, sigs, {zone_name: single})
                break
            except ValidationError as exc:
                failure = exc
        else:
            raise failure or ValidationError(f"DNSKEY RRset of {zone_name} failed validation")
        return _make_rrset(zone_name, _RT.DNSKEY, rrset.ttl, [k for k in rrset if _usable_key(k)])


# =========================================================
# CONVENIENCE API AND CLI
# =========================================================

def dns_lookup(domain: str, qtype: str = "A", config: Optional[ResolverConfig] = None) -> Result:
    """One-shot helper equivalent to ``Resolver(config).resolve(domain, qtype)``."""
    return Resolver(config).resolve(domain, qtype)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Iterative DNS resolver with DNSSEC validation")
    parser.add_argument("domain")
    parser.add_argument("-t", "--type", default="A", dest="qtype")
    parser.add_argument("--root-key", help="trust anchor file (default: root.key beside the script)")
    parser.add_argument("--timeout", type=float, default=ResolverConfig.timeout)
    parser.add_argument("--no-validate", action="store_true", help="skip DNSSEC validation")
    parser.add_argument("--require-dnssec", action="store_true", help="fail on insecure zones")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=(logging.WARNING, logging.INFO, logging.DEBUG)[min(args.verbose, 2)],
        format="%(levelname)s %(message)s",
    )
    try:
        config = ResolverConfig(
            timeout=args.timeout,
            trust_anchor_path=args.root_key,
            validate=not args.no_validate,
            require_dnssec=args.require_dnssec,
        )
        result = Resolver(config).resolve(args.domain, args.qtype)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValidationError as exc:
        print(f"DNSSEC failure: {exc}", file=sys.stderr)
        return 4
    except ResolverError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(result.format())
    return 3 if result.nxdomain else 0


if __name__ == "__main__":
    sys.exit(main())
