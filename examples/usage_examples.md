# Intrusion Detection — usage examples

Run the detector against the bundled sample feed (`examples/captured-traffic.csv`)
or a feed of your own. **Educational use only** — analyze data you own.

## Basic run

```bash
python ids_demo.py examples/captured-traffic.csv
```

## Only high-severity alerts

```bash
python ids_demo.py examples/captured-traffic.csv --min-severity 3
```

## Machine-readable JSON

```bash
python ids_demo.py examples/captured-traffic.csv --json --no-color
```

## Toggle rules

```bash
# Only port-scan and flood detection.
python ids_demo.py examples/captured-traffic.csv --enable port_scan --enable flood

# Everything except noisier rules.
python ids_demo.py examples/captured-traffic.csv --disable beacon --disable distributed
```

## Top 3 alerts only

```bash
python ids_demo.py examples/captured-traffic.csv --top 3
```

## Different input formats

```bash
# JSON feed
python ids_demo.py traffic.json --input-format json
# netflow whitespace format
python ids_demo.py feed.txt --input-format netflow
```

## Quiet / scripting mode

```bash
python ids_demo.py examples/captured-traffic.csv --quiet
echo $?   # 0 = clean, 1 = suspicious, 2 = usage/parse error
```
