# EZproxy Log File Bulk Analyzer

A Python script co-authored with Claude Sonnet 4.6 to analyze EZproxy logfiles.

Parses and analyzes EZproxy access logs to produce comprehensive summary statistics,
top users, top resources, traffic trends, and error reports. Supports multiple input
log formats and exports results to text, CSV, JSON, or Excel formats.

## Input log formats supported:
- EZproxy default: "%h %l %u %t \"%r\" %s %b"
- EZproxy extended (with referrer and user-agent)
- SPU (Starting Point URL) log format

## Output formats:
- text: Formatted text report (default, to stdout or file)
- csv:  Comma-separated values with sections for each data category
- json: Structured JSON with all metrics and trending data
- xlsx: Multi-sheet Excel workbook with formatted tables

## Usage:
```
  python ezproxy_analyzer.py [options] <logfile_or_directory> [logfile2 ...]
```

## Examples:
```
  python ezproxy_analyzer.py /var/log/ezproxy/
  python ezproxy_analyzer.py ezproxy.log.2024-01 ezproxy.log.2024-02
  python ezproxy_analyzer.py --output report.csv --format csv /logs/
  python ezproxy_analyzer.py --output report.xlsx --format xlsx --top 20 /logs/
  python ezproxy_analyzer.py --output report.json --format json /logs/
  python ezproxy_analyzer.py --top 20 --since 2024-01-01 --until 2024-12-31 /logs/
  python ezproxy_analyzer.py --exclude-users exclude_list.txt --format xlsx /logs/
```
