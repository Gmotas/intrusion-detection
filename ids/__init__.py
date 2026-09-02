"""
ids — detection engine for the Intrusion Detection Demo.

This package ingests network traffic feeds and flags unusual patterns using
simple heuristic and statistical detection. It is deliberately dependency-free
(standard library only) so the tool runs anywhere with Python 3.10+.

Modules:
* :mod:`ids.models`  — traffic record and alert data structures.
* :mod:`ids.detector`— the anomaly detection rules.
* :mod:`ids.io`      — CSV / JSON / netflow-text feed readers.
* :mod:`ids.reporter`— human-readable and JSON output.
"""

__version__ = "1.0.0"
