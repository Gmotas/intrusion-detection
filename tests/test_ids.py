"""
Unit tests for the Intrusion Detection Demo.

The detection rules are tested with synthetic traffic feeds. No network access
is required.
"""

from ids import io
from ids.models import TrafficRecord
from ids.detector import Detector, DetectorConfig
from ids.models import HIGH, MEDIUM, CRITICAL

# --- io readers --------------------------------------------------------------
CSV_TEXT = [
    "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes,flags\n",
    "2024-01-01 08:00:00,10.0.0.5,49152,192.168.1.10,80,HTTP,1200,\n",
    "2024-01-01 08:00:01,10.0.0.6,49153,192.168.1.10,443,HTTPS,2200,\n",
]


def test_read_csv():
    recs = list(io.read_csv(CSV_TEXT))
    assert len(recs) == 2
    assert recs[0].src_ip == "10.0.0.5"
    assert recs[0].protocol == "HTTP"
    assert recs[0].bytes == 1200


def test_read_csv_skips_bad_rows():
    bad = [
        "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes,flags\n",
        "not-a-row\n",
        "2024-01-01 08:00:00,10.0.0.5,49152,192.168.1.10,80,HTTP,1200,\n",
    ]
    recs = list(io.read_csv(bad))
    assert len(recs) == 1


def test_read_netflow():
    text = [
        "# a comment\n",
        "2024-01-01 08:00:00 10.0.0.5 49152 192.168.1.10 80 HTTP 1200\n",
        "2024-01-01 08:00:01 10.0.0.6 49153 192.168.1.10 443 HTTPS 2200 SYN\n",
    ]
    recs = list(io.read_netflow(text))
    assert len(recs) == 2
    assert recs[1].is_syn is True


def test_read_json():
    text = ['[{"timestamp":"2024-01-01 08:00:00","src_ip":"10.0.0.5","src_port":49152,"dst_ip":"192.168.1.10","dst_port":80,"protocol":"HTTP","bytes":1200,"flags":""}]']
    recs = list(io.read_json(text))
    assert len(recs) == 1


# --- detector: port scan -----------------------------------------------------
def _portscan_records(base_ts=0):
    import datetime as dt
    base = dt.datetime(2024, 1, 1, 8, 0, 0)
    recs = []
    for i, port in enumerate(range(5000, 5100)):
        recs.append(
        TrafficRecord(
                timestamp=base + dt.timedelta(seconds=i),
                src_ip="10.0.0.66",
                src_port=40000 + i,
                dst_ip="192.168.1.10",
                dst_port=port,
                protocol="TCP",
                bytes=64,
                flags="SYN",
            )
        )
    return recs


def test_detect_port_scan():
    det = Detector(DetectorConfig(port_scan_threshold=15, scan_window_seconds=600))
    alerts = det.analyze(_portscan_records())
    assert any(a.alert_type == "port-scan" for a in alerts)


# --- detector: connection flood ----------------------------------------------
def _flood_records(n=60):
    import datetime as dt
    base = dt.datetime(2024, 1, 1, 8, 0, 0)
    return [
        TrafficRecord(
            timestamp=base + dt.timedelta(seconds=i),
            src_ip="10.0.2.90",
            src_port=50000 + i,
            dst_ip="192.168.1.10",
            dst_port=80,
            protocol="TCP",
            bytes=60,
            flags="SYN",
        )
        for i in range(n)
    ]


def test_detect_flood():
    det = Detector(DetectorConfig(flood_attempts=40, flood_window_seconds=120))
    alerts = det.analyze(_flood_records())
    assert any(a.alert_type == "connection-flood" for a in alerts)


# --- detector: protocol mismatch ---------------------------------------------
def test_detect_protocol_mismatch():
    import datetime as dt
    rec = TrafficRecord(
        timestamp=dt.datetime(2024, 1, 1, 8, 0, 0),
        src_ip="10.0.3.15",
        src_port=51000,
        dst_ip="192.168.1.10",
        dst_port=80,
        protocol="RDP",
        bytes=300,
        flags="SYN",
    )
    det = Detector()
    det.add(rec)
    alerts = det.finalize()
    assert any(a.alert_type == "protocol-mismatch" for a in alerts)


# --- detector: large transfer ------------------------------------------------
def test_detect_large_transfer():
    import datetime as dt
    base = dt.datetime(2024, 1, 1, 8, 0, 0)
    # Ten small transfers plus one clear outlier; the outlier's z-score is > 3.
    recs = [
        TrafficRecord(base + dt.timedelta(seconds=i), "10.0.4.10", 52000 + i,
                          "192.168.1.10", 8080, "HTTP", bytes_, None)
        for i, bytes_ in enumerate([1000, 1000, 1000, 1000, 1000,
                                    1000, 1000, 1000, 1000, 1000, 500000])
    ]
    det = Detector(DetectorConfig(large_transfer_z=3.0, large_transfer_min_bytes=10000))
    alerts = det.analyze(recs)
    assert any(a.alert_type == "large-transfer" for a in alerts)


# --- detector: distributed scan ---------------------------------------------
def test_detect_distributed():
    import datetime as dt
    base = dt.datetime(2024, 1, 1, 8, 0, 0)
    recs = [
        TrafficRecord(base + dt.timedelta(seconds=i), f"10.0.5.{i}", 53000 + i,
                          "192.168.1.20", 443, "HTTPS", 2000, None)
        for i in range(1, 12)
    ]
    det = Detector(DetectorConfig(distributed_sources=8))
    alerts = det.analyze(recs)
    assert any(a.alert_type == "distributed-scan" for a in alerts)


# --- severity / ordering -----------------------------------------------------
def test_alerts_sorted_by_severity():
    import datetime as dt
    base = dt.datetime(2024, 1, 1, 8, 0, 0)
    recs = []
    for i, port in enumerate(range(5000, 5100)):
        recs.append(TrafficRecord(base + dt.timedelta(seconds=i), "10.0.0.66", 40000 + i,
                                     "192.168.1.10", port, "TCP", 64, "SYN"))
    det = Detector()
    alerts = det.analyze(recs)
    sevs = [a.severity for a in alerts]
    assert sevs == sorted(sevs, reverse=True)
