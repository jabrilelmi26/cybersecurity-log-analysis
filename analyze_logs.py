"""Defensive analysis of synthetic CSV authentication events; no live system access."""
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
WINDOW = timedelta(minutes=10)
MIN_FAILURES = 3

def parse_time(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)

def find_alerts(events):
    parsed = [{**event, 'time': parse_time(event['timestamp'])} for event in events]
    parsed.sort(key=lambda e: e['time'])
    alerts = []
    keys = sorted({(e['user'], e['source_ip']) for e in parsed})
    for user, ip in keys:
        relevant = [e for e in parsed if e['user'] == user and e['source_ip'] == ip]
        fails = [e for e in relevant if e['event'] == 'failure']
        # Sliding window; report the earliest qualifying span per user/IP.
        for index, first in enumerate(fails):
            window_fails = [e for e in fails[index:] if e['time'] - first['time'] <= WINDOW]
            if len(window_fails) >= MIN_FAILURES:
                last_failure = window_fails[-1]['time']
                later_success = next((e for e in relevant if e['event'] == 'success' and last_failure <= e['time'] <= last_failure + WINDOW), None)
                alerts.append({
                    'user': user, 'source_ip': ip,
                    'first_failure': first['timestamp'],
                    'failed_attempts_in_window': len(window_fails),
                    'success_after_failures': bool(later_success),
                    'assessment': 'Review authentication context; not proof of compromise'
                })
                break
    return alerts

def main():
    with (HERE / 'events.csv').open(newline='', encoding='utf-8') as f:
        events = list(csv.DictReader(f))
    alerts = find_alerts(events)
    (HERE / 'findings.json').write_text(json.dumps(alerts, indent=2) + '\n', encoding='utf-8')
    print(f'Analyzed {len(events)} synthetic authentication events; {len(alerts)} alert(s).')
    for a in alerts:
        print(f"Review {a['user']} from {a['source_ip']}: {a['failed_attempts_in_window']} failures; later success={a['success_after_failures']}")

if __name__ == '__main__':
    main()
