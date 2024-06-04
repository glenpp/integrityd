#!/usr/bin/env python3
"""
Check Plugin (Nagios API)
"""

import sys
import time
import yaml


def usage():
    print(f"Usage: {sys.argv[0]} <report file> <warn time> <critical time>", file=sys.stderr)
    sys.exit(3)


def main():
    if len(sys.argv) != 4:
        usage()
    report_file = sys.argv[1]
    try:
        warn_above = int(sys.argv[2])
        critical_above = int(sys.argv[3])
    except ValueError:
        usage()
    try:
        with open(report_file, 'rt') as f_report:
            report = yaml.safe_load(f_report)
    except FileNotFoundError:
        print("UNKNOWN: Missing report file")
        sys.exit(3)
    except PermissionError:
        print("UNKNOWN: Permissions prevent reding report file")
        sys.exit(3)
    report_age = int(time.time() - report['finish_time'])
    if report_age > critical_above:
        print(f"CRITICAL: Age {report_age} > {critical_above}")
        sys.exit(2)
    if report_age > warn_above:
        print(f"WARNING: Age {report_age} > {warn_above}")
        sys.exit(1)
    print(f"OK: Age {report_age / 3600:.1f}h")
    sys.exit(0)


if __name__ == '__main__':
    main()
