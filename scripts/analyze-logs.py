#!/usr/bin/env python3
"""
Suricata Log Analysis Script

This script analyzes Suricata's eve.json log file and provides statistics and insights.

Features:
- Parse eve.json log files
- Display top alerts with counts
- Show statistics (protocols, source/destination IPs, ports)
- Filter by alert severity/priority
- Export reports to CSV or JSON format

Usage Examples:
    # Basic analysis
    ./analyze-logs.py --file /var/log/suricata/eve.json

    # Show top 20 alerts
    ./analyze-logs.py --file eve.json --top 20

    # Filter by severity (1=high, 2=medium, 3=low)
    ./analyze-logs.py --file eve.json --filter severity:1

    # Export to CSV
    ./analyze-logs.py --file eve.json --export alerts.csv

    # Export to JSON
    ./analyze-logs.py --file eve.json --export report.json

    # Combine options
    ./analyze-logs.py --file eve.json --top 10 --filter priority:1 --export high_priority.csv

Requirements:
    Python 3.7+
    No external dependencies (uses standard library only)
"""

import json
import argparse
import sys
import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional


class SuricataLogAnalyzer:
    """Analyze Suricata eve.json log files."""

    def __init__(self, log_file: str):
        """Initialize the analyzer with a log file path."""
        self.log_file = Path(log_file)
        self.events = []
        self.alerts = []
        self.stats = {
            'total_events': 0,
            'total_alerts': 0,
            'alert_counts': Counter(),
            'protocols': Counter(),
            'src_ips': Counter(),
            'dest_ips': Counter(),
            'dest_ports': Counter(),
            'severities': Counter(),
            'priorities': Counter(),
        }

    def load_events(self) -> bool:
        """Load events from the eve.json file."""
        if not self.log_file.exists():
            print(f"Error: File not found: {self.log_file}", file=sys.stderr)
            return False

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        self.events.append(event)
                        self.stats['total_events'] += 1

                        # Process alerts
                        if event.get('event_type') == 'alert':
                            self.alerts.append(event)
                            self.stats['total_alerts'] += 1
                            self._process_alert(event)
                        
                        # Process other event types
                        self._process_event(event)

                    except json.JSONDecodeError as e:
                        print(f"Warning: Invalid JSON on line {line_num}: {e}", file=sys.stderr)
                        continue

            print(f"✓ Loaded {self.stats['total_events']} events from {self.log_file}")
            print(f"✓ Found {self.stats['total_alerts']} alerts")
            return True

        except IOError as e:
            print(f"Error: Failed to read file: {e}", file=sys.stderr)
            return False

    def _process_alert(self, event: Dict[str, Any]) -> None:
        """Process an alert event and update statistics."""
        alert = event.get('alert', {})
        
        # Alert signature
        signature = alert.get('signature', 'Unknown')
        self.stats['alert_counts'][signature] += 1
        
        # Severity and priority
        severity = alert.get('severity', 0)
        priority = alert.get('priority', 0)
        self.stats['severities'][severity] += 1
        self.stats['priorities'][priority] += 1

    def _process_event(self, event: Dict[str, Any]) -> None:
        """Process general event information and update statistics."""
        # Protocol
        proto = event.get('proto', 'unknown').upper()
        self.stats['protocols'][proto] += 1
        
        # Source IP
        src_ip = event.get('src_ip')
        if src_ip:
            self.stats['src_ips'][src_ip] += 1
        
        # Destination IP
        dest_ip = event.get('dest_ip')
        if dest_ip:
            self.stats['dest_ips'][dest_ip] += 1
        
        # Destination port
        dest_port = event.get('dest_port')
        if dest_port:
            self.stats['dest_ports'][dest_port] += 1

    def filter_alerts(self, filter_str: Optional[str]) -> List[Dict[str, Any]]:
        """Filter alerts based on criteria."""
        if not filter_str:
            return self.alerts

        filtered = self.alerts
        
        try:
            # Parse filter string (format: "key:value")
            parts = filter_str.split(':', 1)
            if len(parts) != 2:
                print(f"Warning: Invalid filter format: {filter_str}", file=sys.stderr)
                return filtered

            key, value = parts
            key = key.lower().strip()
            value = value.strip()

            if key == 'severity':
                severity_val = int(value)
                filtered = [a for a in filtered if a.get('alert', {}).get('severity') == severity_val]
            elif key == 'priority':
                priority_val = int(value)
                filtered = [a for a in filtered if a.get('alert', {}).get('priority') == priority_val]
            elif key == 'signature':
                filtered = [a for a in filtered if value.lower() in a.get('alert', {}).get('signature', '').lower()]
            elif key == 'src_ip':
                filtered = [a for a in filtered if a.get('src_ip') == value]
            elif key == 'dest_ip':
                filtered = [a for a in filtered if a.get('dest_ip') == value]
            else:
                print(f"Warning: Unknown filter key: {key}", file=sys.stderr)

        except ValueError as e:
            print(f"Warning: Invalid filter value: {e}", file=sys.stderr)

        return filtered

    def display_top_alerts(self, top_n: int = 10, filter_str: Optional[str] = None) -> None:
        """Display top N alerts."""
        filtered_alerts = self.filter_alerts(filter_str)
        
        if not filtered_alerts:
            print("\nNo alerts found matching the filter criteria.")
            return

        # Count alerts in filtered set
        alert_counter = Counter()
        for alert in filtered_alerts:
            signature = alert.get('alert', {}).get('signature', 'Unknown')
            alert_counter[signature] += 1

        print(f"\n{'='*80}")
        print(f"TOP {top_n} ALERTS")
        if filter_str:
            print(f"Filter: {filter_str}")
        print(f"{'='*80}\n")
        
        print(f"{'Count':<10} {'Alert Signature':<70}")
        print(f"{'-'*10} {'-'*70}")
        
        for signature, count in alert_counter.most_common(top_n):
            # Truncate long signatures
            sig_display = signature[:67] + "..." if len(signature) > 70 else signature
            print(f"{count:<10} {sig_display}")

    def display_statistics(self) -> None:
        """Display general statistics."""
        print(f"\n{'='*80}")
        print("STATISTICS")
        print(f"{'='*80}\n")

        # Protocol distribution
        print("Top Protocols:")
        print(f"  {'Protocol':<15} {'Count':<10}")
        print(f"  {'-'*15} {'-'*10}")
        for proto, count in self.stats['protocols'].most_common(10):
            print(f"  {proto:<15} {count:<10}")

        # Top source IPs
        print("\nTop Source IPs:")
        print(f"  {'IP Address':<20} {'Count':<10}")
        print(f"  {'-'*20} {'-'*10}")
        for ip, count in self.stats['src_ips'].most_common(10):
            print(f"  {ip:<20} {count:<10}")

        # Top destination IPs
        print("\nTop Destination IPs:")
        print(f"  {'IP Address':<20} {'Count':<10}")
        print(f"  {'-'*20} {'-'*10}")
        for ip, count in self.stats['dest_ips'].most_common(10):
            print(f"  {ip:<20} {count:<10}")

        # Top destination ports
        print("\nTop Destination Ports:")
        print(f"  {'Port':<10} {'Count':<10}")
        print(f"  {'-'*10} {'-'*10}")
        for port, count in self.stats['dest_ports'].most_common(10):
            print(f"  {port:<10} {count:<10}")

        # Severity distribution
        if self.stats['severities']:
            print("\nAlert Severity Distribution:")
            print(f"  {'Severity':<15} {'Count':<10}")
            print(f"  {'-'*15} {'-'*10}")
            severity_names = {1: "High", 2: "Medium", 3: "Low"}
            for severity, count in sorted(self.stats['severities'].items()):
                name = severity_names.get(severity, f"Unknown ({severity})")
                print(f"  {name:<15} {count:<10}")

        # Priority distribution
        if self.stats['priorities']:
            print("\nAlert Priority Distribution:")
            print(f"  {'Priority':<15} {'Count':<10}")
            print(f"  {'-'*15} {'-'*10}")
            for priority, count in sorted(self.stats['priorities'].items()):
                print(f"  {priority:<15} {count:<10}")

    def export_csv(self, output_file: str, filter_str: Optional[str] = None) -> bool:
        """Export alerts to CSV format."""
        filtered_alerts = self.filter_alerts(filter_str)
        
        if not filtered_alerts:
            print("No alerts to export.", file=sys.stderr)
            return False

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'timestamp', 'src_ip', 'src_port', 'dest_ip', 'dest_port',
                    'proto', 'signature', 'severity', 'priority', 'category'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for alert in filtered_alerts:
                    alert_data = alert.get('alert', {})
                    row = {
                        'timestamp': alert.get('timestamp', ''),
                        'src_ip': alert.get('src_ip', ''),
                        'src_port': alert.get('src_port', ''),
                        'dest_ip': alert.get('dest_ip', ''),
                        'dest_port': alert.get('dest_port', ''),
                        'proto': alert.get('proto', ''),
                        'signature': alert_data.get('signature', ''),
                        'severity': alert_data.get('severity', ''),
                        'priority': alert_data.get('priority', ''),
                        'category': alert_data.get('category', ''),
                    }
                    writer.writerow(row)

            print(f"✓ Exported {len(filtered_alerts)} alerts to {output_file}")
            return True

        except IOError as e:
            print(f"Error: Failed to write CSV file: {e}", file=sys.stderr)
            return False

    def export_json(self, output_file: str, filter_str: Optional[str] = None) -> bool:
        """Export analysis report to JSON format."""
        filtered_alerts = self.filter_alerts(filter_str)
        
        report = {
            'summary': {
                'total_events': self.stats['total_events'],
                'total_alerts': len(filtered_alerts),
                'filter_applied': filter_str,
            },
            'top_alerts': [
                {'signature': sig, 'count': count}
                for sig, count in Counter(
                    a.get('alert', {}).get('signature', 'Unknown')
                    for a in filtered_alerts
                ).most_common(20)
            ],
            'statistics': {
                'protocols': dict(self.stats['protocols'].most_common(10)),
                'src_ips': dict(self.stats['src_ips'].most_common(10)),
                'dest_ips': dict(self.stats['dest_ips'].most_common(10)),
                'dest_ports': dict(self.stats['dest_ports'].most_common(10)),
                'severities': dict(self.stats['severities']),
                'priorities': dict(self.stats['priorities']),
            },
            'alerts': filtered_alerts[:1000],  # Limit to first 1000 alerts
        }

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)

            print(f"✓ Exported report to {output_file}")
            return True

        except IOError as e:
            print(f"Error: Failed to write JSON file: {e}", file=sys.stderr)
            return False


def main():
    """Main function to run the log analyzer."""
    parser = argparse.ArgumentParser(
        description='Analyze Suricata eve.json log files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file /var/log/suricata/eve.json
  %(prog)s --file eve.json --top 20
  %(prog)s --file eve.json --filter severity:1
  %(prog)s --file eve.json --export alerts.csv
  %(prog)s --file eve.json --export report.json
  %(prog)s --file eve.json --top 10 --filter priority:1 --export high.csv

Filter Options:
  severity:1      High severity alerts
  severity:2      Medium severity alerts  
  severity:3      Low severity alerts
  priority:1      Priority 1 alerts
  src_ip:X.X.X.X  Alerts from specific source IP
  dest_ip:X.X.X.X Alerts to specific destination IP
  signature:TEXT  Alerts matching signature text
        """
    )

    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Path to eve.json log file'
    )

    parser.add_argument(
        '-t', '--top',
        type=int,
        default=10,
        help='Number of top alerts to display (default: 10)'
    )

    parser.add_argument(
        '-F', '--filter',
        help='Filter alerts (format: key:value, e.g., severity:1, priority:1)'
    )

    parser.add_argument(
        '-e', '--export',
        help='Export to file (CSV if ends with .csv, JSON otherwise)'
    )

    parser.add_argument(
        '-s', '--stats-only',
        action='store_true',
        help='Show only statistics, skip alert list'
    )

    args = parser.parse_args()

    # Create analyzer instance
    analyzer = SuricataLogAnalyzer(args.file)

    # Load events
    if not analyzer.load_events():
        sys.exit(1)

    # Display results
    if not args.stats_only:
        analyzer.display_top_alerts(args.top, args.filter)

    analyzer.display_statistics()

    # Export if requested
    if args.export:
        if args.export.endswith('.csv'):
            success = analyzer.export_csv(args.export, args.filter)
        else:
            success = analyzer.export_json(args.export, args.filter)
        
        if not success:
            sys.exit(1)

    print(f"\n{'='*80}")
    print("Analysis complete!")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
