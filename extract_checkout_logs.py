"""
Script to extract checkout endpoint logs from web.log and worker.log,
grouping logs by request_id so related logs are adjacent.
"""

import re
from collections import defaultdict
from datetime import datetime


def parse_web_log_line(line):
    """Parse a web.log line and extract relevant fields."""
    # Pattern for web.log: timestamp INFO [request] method=X path=Y status=Z latency_ms=W user_id=U request_id=R
    pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (\w+) \[(\w+)\] (.*)$'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, level, component, rest = match.groups()
    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
    
    # Extract key-value pairs from the rest of the line
    fields = {}
    kv_pattern = r'(\w+)=([^\s]+)'
    for kv_match in re.finditer(kv_pattern, rest):
        fields[kv_match.group(1)] = kv_match.group(2)
    
    return {
        'timestamp': timestamp,
        'timestamp_str': timestamp_str,
        'level': level,
        'component': component,
        'fields': fields,
        'raw_line': line.strip(),
        'source': 'web.log'
    }


def parse_worker_log_line(line):
    """Parse a worker.log line and extract relevant fields."""
    # Pattern for worker.log: timestamp LEVEL [component] message request_id=X duration_ms=Y
    pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (\w+) \[([^\]]+)\] (.*)$'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, level, component, rest = match.groups()
    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
    
    # Extract request_id if present
    request_id = None
    request_id_match = re.search(r'request_id=([^\s]+)', rest)
    if request_id_match:
        request_id = request_id_match.group(1)
    
    # Extract key-value pairs
    fields = {}
    kv_pattern = r'(\w+)=([^\s]+)'
    for kv_match in re.finditer(kv_pattern, rest):
        fields[kv_match.group(1)] = kv_match.group(2)
    
    return {
        'timestamp': timestamp,
        'timestamp_str': timestamp_str,
        'level': level,
        'component': component,
        'request_id': request_id,
        'fields': fields,
        'raw_line': line.strip(),
        'source': 'worker.log'
    }


def extract_checkout_logs(web_log_path, worker_log_path, output_path):
    """
    Extract checkout endpoint logs and correlate with worker logs.
    Group by request_id so related logs are adjacent.
    """
    
    # Step 1: Read web.log and find all checkout requests
    checkout_request_ids = set()
    checkout_web_logs = []
    
    print(f"Reading {web_log_path}...")
    with open(web_log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parsed = parse_web_log_line(line)
            if parsed and parsed['fields'].get('path') == '/checkout':
                request_id = parsed['fields'].get('request_id')
                if request_id:
                    checkout_request_ids.add(request_id)
                    checkout_web_logs.append(parsed)
    
    print(f"Found {len(checkout_request_ids)} checkout requests in web.log")
    
    # Step 2: Read worker.log and find all logs matching checkout request_ids
    checkout_worker_logs = []
    
    print(f"Reading {worker_log_path}...")
    with open(worker_log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parsed = parse_worker_log_line(line)
            if parsed and parsed['request_id'] in checkout_request_ids:
                checkout_worker_logs.append(parsed)
    
    print(f"Found {len(checkout_worker_logs)} matching worker logs")
    
    # Step 3: Group all logs by request_id
    logs_by_request_id = defaultdict(list)
    
    for log in checkout_web_logs:
        request_id = log['fields'].get('request_id')
        if request_id:
            logs_by_request_id[request_id].append(log)
    
    for log in checkout_worker_logs:
        request_id = log['request_id']
        if request_id:
            logs_by_request_id[request_id].append(log)
    
    # Step 4: Sort logs within each request_id group by timestamp
    for request_id in logs_by_request_id:
        logs_by_request_id[request_id].sort(key=lambda x: x['timestamp'])
    
    # Step 5: Sort request_ids by their first log timestamp
    sorted_request_ids = sorted(
        logs_by_request_id.keys(),
        key=lambda rid: logs_by_request_id[rid][0]['timestamp']
    )
    
    # Step 6: Write output file with logs grouped by request_id
    print(f"Writing output to {output_path}...")
    
    total_log_lines = 0
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("=" * 100 + "\n")
        f.write("CHECKOUT ENDPOINT LOGS - Grouped by Request ID\n")
        f.write(f"Total Checkout Requests: {len(sorted_request_ids)}\n")
        f.write("=" * 100 + "\n\n")
        
        for request_id in sorted_request_ids:
            logs = logs_by_request_id[request_id]
            
            f.write("-" * 80 + "\n")
            f.write(f"REQUEST_ID: {request_id}\n")
            f.write(f"Log Count: {len(logs)}\n")
            f.write("-" * 80 + "\n")
            
            for log in logs:
                f.write(f"[{log['source']}] {log['raw_line']}\n")
                total_log_lines += 1
            
            f.write("\n")
        
        f.write("=" * 100 + "\n")
        f.write(f"END OF REPORT - Total log lines: {total_log_lines}\n")
        f.write("=" * 100 + "\n")
    
    print(f"Done! Total log lines written: {total_log_lines}")
    print(f"Output saved to: {output_path}")
    
    return {
        'total_checkout_requests': len(sorted_request_ids),
        'web_log_entries': len(checkout_web_logs),
        'worker_log_entries': len(checkout_worker_logs),
        'total_log_lines': total_log_lines
    }


if __name__ == '__main__':
    import os
    
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    web_log_path = os.path.join(script_dir, 'web.log')
    worker_log_path = os.path.join(script_dir, 'worker.log')
    output_path = os.path.join(script_dir, 'checkout_logs.log')
    
    stats = extract_checkout_logs(web_log_path, worker_log_path, output_path)
    
    print("\n--- Summary ---")
    print(f"Total checkout requests: {stats['total_checkout_requests']}")
    print(f"Web log entries: {stats['web_log_entries']}")
    print(f"Worker log entries: {stats['worker_log_entries']}")
    print(f"Total log lines: {stats['total_log_lines']}")
