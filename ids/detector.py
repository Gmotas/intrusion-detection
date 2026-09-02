"""
ids/detector — anomaly detection rules.

The detector aggregates :class:`~ids.models.TrafficRecord` objects over a
sliding time window and emits :class:`~ids.models.Alert` objects.

Rules implemented (each can be toggled):

* port_scan      — one source contacts many distinct dst ports in a window.
* flood          — high rate of connection attempts (SYN) from one source.
* beacon         — a source talks to one destination at near-regular intervals.
* large_transfer — a connection pushes bytes far above that source's baseline
                   (z-score over the source's own transfer history).
* protocol_mismatch — traffic whose protocol does not match the destination
                   port's well-known service.
* distributed    — many distinct sources target a single destination in a window.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ids.models import Alert, HIGH, MEDIUM, LOW, CRITICAL, TrafficRecord

# Well-known port -> expected protocol (for protocol-mismatch detection).
EXPECTED_PROTOCOL = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    6379: "REDIS",
    8080: "HTTP",
}


@dataclass
class DetectorConfig:
    """Tunable parameters for all detection rules."""

    window_seconds: int = 300
    port_scan_threshold: int = 15          # distinct dst ports per source
    scan_window_seconds: int = 300
    flood_attempts: int = 40               # SYN attempts in window
    flood_window_seconds: int = 60
    beacon_interval_std: float = 1.0       # std-dev (seconds) below which the pattern is "regular"
    beacon_min_observations: int = 5       # beacon needs this many contacts
    large_transfer_z: float = 3.0          # z-score threshold
    large_transfer_min_bytes: int = 50_000
    distributed_sources: int = 8           # distinct sources hitting one host
    distributed_window_seconds: int = 300
    enabled_rules: set[str] = field(default_factory=lambda: {
        "port_scan", "flood", "beacon", "large_transfer",
        "protocol_mismatch", "distributed",
    })


class Detector:
    """Stateful anomaly detector over a stream of traffic records."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self.alerts: list[Alert] = []
        self._all: list[TrafficRecord] = []
        self._seen_alert_keys: set[tuple] = set()

    # --- public API --------------------------------------------------------
    def add(self, rec: TrafficRecord) -> None:
        self._all.append(rec)
        if "port_scan" in self.config.enabled_rules:
            self._detect_port_scan(rec)
        if "flood" in self.config.enabled_rules:
            self._detect_flood(rec)
        if "protocol_mismatch" in self.config.enabled_rules:
            self._detect_protocol_mismatch(rec)
        # Windowed / statistical rules run at the end via finalize().

    def analyze(self, records) -> list[Alert]:
        for rec in records:
            self.add(rec)
        return self.finalize()

    def finalize(self) -> list[Alert]:
        """Run rules that need the full record set and return sorted alerts."""
        if "beacon" in self.config.enabled_rules:
            self._detect_beacons()
        if "large_transfer" in self.config.enabled_rules:
            self._detect_large_transfers()
        if "distributed" in self.config.enabled_rules:
            self._detect_distributed()
        return sorted(self.alerts, key=lambda a: (a.severity, a.ts or datetime.min), reverse=True)

    # --- helpers -----------------------------------------------------------
    def _emit(self, alert_type: str, severity: int, src: str | None, dst: str | None,
              summary: str, evidence: list[str], ts: datetime | None, count: int) -> None:
        key = (alert_type, src, dst, summary)
        if key in self._seen_alert_keys:
            # Refresh the existing alert's count/evidence rather than dup.
            for existing in reversed(self.alerts):
                if (existing.alert_type, existing.src_ip, existing.dst_ip, existing.summary) == key:
                    existing.count = max(existing.count, count)
                    existing.evidence = evidence[:5]
                    return
        self._seen_alert_keys.add(key)
        self.alerts.append(Alert(
            alert_type=alert_type,
            severity=severity,
            src_ip=src,
            dst_ip=dst,
            summary=summary,
            evidence=evidence,
            ts=ts,
            count=count,
        ))

    def _window_records(self, now: datetime, seconds: int) -> list[TrafficRecord]:
        cutoff = now - timedelta(seconds=seconds)
        return [r for r in self._all if r.timestamp >= cutoff and r.timestamp <= now]

    # --- per-record rules --------------------------------------------------
    def _detect_port_scan(self, rec: TrafficRecord) -> None:
        window = self._window_records(rec.timestamp, self.config.scan_window_seconds)
        src_ports: dict[str, set] = defaultdict(set)
        for r in window:
            src_ports[r.src_ip].add(r.dst_port)
        if len(src_ports.get(rec.src_ip, set())) >= self.config.port_scan_threshold:
            self._emit(
                "port-scan", HIGH, rec.src_ip, None,
                f"{rec.src_ip} contacted {len(src_ports[rec.src_ip])} distinct ports in window",
                [self._fmt(r) for r in window if r.src_ip == rec.src_ip][-5:],
                rec.timestamp, len(src_ports[rec.src_ip]),
            )

    def _detect_flood(self, rec: TrafficRecord) -> None:
        window = self._window_records(rec.timestamp, self.config.flood_window_seconds)
        syn_counts: dict[str, int] = Counter()
        for r in window:
            if r.is_syn:
                syn_counts[r.src_ip] += 1
        if syn_counts.get(rec.src_ip, 0) >= self.config.flood_attempts:
            self._emit(
                "connection-flood", HIGH, rec.src_ip, None,
                f"{rec.src_ip} sent {syn_counts[rec.src_ip]} SYN attempts in {self.config.flood_window_seconds}s",
                [self._fmt(r) for r in window if r.src_ip == rec.src_ip and r.is_syn][-5:],
                rec.timestamp, syn_counts[rec.src_ip],
            )

    def _detect_protocol_mismatch(self, rec: TrafficRecord) -> None:
        expected = EXPECTED_PROTOCOL.get(rec.dst_port)
        if expected is None:
            return
        if rec.protocol and rec.protocol != expected and rec.protocol not in ("TCP", "UDP", "IP"):
            self._emit(
                "protocol-mismatch", MEDIUM, rec.src_ip, rec.dst_ip,
                f"protocol {rec.protocol} on port {rec.dst_port} (expected {expected})",
                [self._fmt(rec)], rec.timestamp, 1,
            )

    # --- full-set rules ----------------------------------------------------
    def _detect_beacons(self) -> None:
        # Group contacts (src, dst, protocol) and look for a regular interval.
        groups: dict[tuple, list[datetime]] = defaultdict(list)
        for r in self._all:
            groups[(r.src_ip, r.dst_ip, r.protocol)].append(r.timestamp)
        for (src, dst, proto), stamps in groups.items():
            stamps = sorted(stamps)
            if len(stamps) < self.config.beacon_min_observations:
                continue
            gaps = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])]
            gaps = [g for g in gaps if g > 0]
            if not gaps:
                continue
            try:
                std = statistics.pstdev(gaps)
            except statistics.StatisticsError:
                continue
            if std <= self.config.beacon_interval_std:
                self._emit(
                    "beacon", MEDIUM, src, dst,
                    f"beacon: {src}->{dst}@{proto} at regular ~{statistics.mean(gaps):.1f}s intervals",
                    [self._fmt(r) for r in self._all if r.src_ip == src and r.dst_ip == dst][-5:],
                    stamps[-1], len(stamps),
                )

    def _detect_large_transfers(self) -> None:
        # Per-(src,dst) baseline of transfer sizes; flag z-score outliers.
        pairs: dict[tuple, list[int]] = defaultdict(list)
        for r in self._all:
            pairs[(r.src_ip, r.dst_ip)].append(r.bytes)
        for (src, dst), sizes in pairs.items():
            if len(sizes) < 2:
                continue
            mean = statistics.mean(sizes)
            if mean <= 0:
                continue
            try:
                std = statistics.pstdev(sizes)
            except statistics.StatisticsError:
                std = 0.0
            for r in self._all:
                if r.src_ip == src and r.dst_ip == dst and r.bytes >= self.config.large_transfer_min_bytes:
                    if std == 0 and r.bytes > mean:
                        z = 99.0
                    elif std > 0:
                        z = (r.bytes - mean) / std
                    else:
                        continue
                    if z >= self.config.large_transfer_z:
                        self._emit(
                            "large-transfer", HIGH, src, dst,
                            f"{src}->{dst} sent {r.bytes} bytes (z={z:.1f}, baseline mean={mean:.0f})",
                            [self._fmt(r)], r.timestamp, r.bytes,
                        )
                        break

    def _detect_distributed(self) -> None:
        # Count distinct sources per destination within a window.
        by_dst: dict[str, dict[str, int]] = defaultdict(dict)
        for r in self._all:
            by_dst[r.dst_ip][r.src_ip] = max(by_dst[r.dst_ip].get(r.src_ip, 0), r.bytes)
        for dst, srcs in by_dst.items():
            if len(srcs) >= self.config.distributed_sources:
                last = max(r.timestamp for r in self._all if r.dst_ip == dst)
                self._emit(
                    "distributed-scan", HIGH, None, dst,
                    f"{len(srcs)} distinct sources targeted {dst} in the feed",
                    [f"{s} ({b} bytes)" for s, b in list(srcs.items())[:5]],
                    last, len(srcs),
                )

    @staticmethod
    def _fmt(r: TrafficRecord) -> str:
        flags = f" {r.flags}" if r.flags else ""
        return f"{r.timestamp.isoformat(timespec='seconds')} {r.src_ip}:{r.src_port} -> {r.dst_ip}:{r.dst_port} {r.protocol} {r.bytes}B{flags}"
