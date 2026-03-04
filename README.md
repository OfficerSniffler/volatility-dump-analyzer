# Volatility Dump Analyzer #

GUI tool for triage analysis of Volatility3 `windows.netstat` CSV output.

The tool aggregates network connections found in RAM dumps and highlights
potential anomalies such as suspicious processes, ports, and process chains.

## Features

- Netstat CSV analysis (Volatility3)
- Aggregation of IP connections
- Highlighting suspicious processes and ports
- Top talker detection
- Process chain preview
- PID correlation using:
  - windows.pslist
  - windows.cmdline
  - windows.pstree
- Optional GeoIP enrichment via GeoLite2

## Requirements

Python 3.10+

