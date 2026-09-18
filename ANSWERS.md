# Infollion Assignment-1 Answers

## 1. When did the problem start? Include the timestamp and the evidence you used.
Ans: The problem started at 2026-07-02 14:32:40(from web.log file). I am saying this because when I segregated error logs from info logs, I got two types of errors, one is metric error( which can be because metric is not getting update) and another is upstream call failed request( whose request id match with checkout endpoint requests in web.log ). And as mentioned orders are getting placed but some never appeared in system, so there is problem in processing those orders after checkout. 

## 2. Which endpoint is affected? Support your answer with evidence from the logs.
Ans: /checkout endpoint is affected. As 100% actual incident failures target the checkout endpoint . In logs there are 2385 failed asynchronous checkout transactions which has 202 status in web.log but dropped or failed in worker.log

## 3. What do the failing requests have in common? Identify the pattern and support it with numbers.
Ans: There are multiple things that are common among failing requests. Some are:
1. All requests have status code 202 in web.log file
2. All failing requests are trying to connect to same upstream server with ip 10.0.3.44:8443
3. 2385 checkout transaction requests got failed.
4. All 100% failed requests share the same error signature. 


## 4. How many distinct users were affected?
Ans: 2,335 distinct users were impacted by failed checkout orders.

## Bonus: Is there anything in the logs that suggests the root cause?
Ans: Root cause of this problem is upstream network reset issue when background worker is trying to connect with the upstream ip 10.0.3.44:8443. Because of this customer requests get 202 status for their request which makes user believe that their order got placed. But background worker is getting failed silently to process the order because of which that order never got stored in the system. 

## Data of first failed transaction

02-07-2026  14:32:40	INFO	request	43438	method=POST path=/checkout status=202 latency_ms=36 user_id=59787 request_id=16ce72300cf58a32	POST	/checkout	202	36	59787	16ce72300cf58a32	32:42.7	ERROR	worker	12361	upstream call failed request_id=16ce72300cf58a32 err=ECONNRESET upstream=10.0.3.44:8443 (retries exhausted)				ECONNRESET	10.0.3.44:8443	both	matched


## Script ( Script is generated using ai tools with manual review )

```python

#!/usr/bin/env python3
"""
Log Forensic Analysis Script
============================
Analyzes web.log and worker.log files to identify patterns, failures,
and correlate requests across systems.

Author: Log Analysis Tool
Purpose: Data forensic analysis for production incident investigation
"""

import re
import pandas as pd
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import argparse


# =============================================================================
# PARSING FUNCTIONS
# =============================================================================

def parse_web_log(filepath: str) -> pd.DataFrame:
    """
    Parse web.log file and extract structured data.
    
    Expected format:
    2026-07-02 00:00:01.331 INFO [request] method=GET path=/products status=200 
    latency_ms=32 user_id=15416 request_id=5f9a2404502fb9b8
    """
    records = []
    
    # Pattern for request logs
    request_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+'  # timestamp
        r'(\w+)\s+'                                          # log level
        r'\[(\w+)\]\s+'                                      # component
        r'(.+)'                                              # rest of message
    )
    
    # Pattern for key=value pairs
    kv_pattern = re.compile(r'(\w+)=([^\s]+)')
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            match = request_pattern.match(line)
            if match:
                timestamp_str, level, component, message = match.groups()
                
                record = {
                    'timestamp': datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f'),
                    'level': level,
                    'component': component,
                    'line_num': line_num,
                    'raw_message': message
                }
                
                # Extract key-value pairs
                for kv_match in kv_pattern.finditer(message):
                    key, value = kv_match.groups()
                    # Convert numeric values
                    if key in ['status', 'latency_ms', 'user_id']:
                        try:
                            value = int(value)
                        except ValueError:
                            pass
                    record[key] = value
                
                records.append(record)
    
    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values('timestamp').reset_index(drop=True)
    return df


def parse_worker_log(filepath: str) -> pd.DataFrame:
    """
    Parse worker.log file and extract structured data.
    
    Expected formats:
    - Job completed: 2026-07-02 00:00:12.957 INFO [worker] job completed request_id=xxx duration_ms=1713
    - Errors: 2026-07-02 00:00:21.000 ERROR [metrics-worker] AnalyticsUploadTimeout: ...
    """
    records = []
    
    # General log pattern
    log_pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+'  # timestamp
        r'(\w+)\s+'                                          # log level
        r'\[([^\]]+)\]\s+'                                   # component
        r'(.+)'                                              # message
    )
    
    # Pattern for key=value pairs
    kv_pattern = re.compile(r'(\w+)=([^\s]+)')
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            match = log_pattern.match(line)
            if match:
                timestamp_str, level, component, message = match.groups()
                
                record = {
                    'timestamp': datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f'),
                    'level': level,
                    'component': component,
                    'line_num': line_num,
                    'raw_message': message,
                    'job_status': None,
                    'error_type': None
                }
                
                # Determine job status
                if 'job completed' in message.lower():
                    record['job_status'] = 'completed'
                elif 'job failed' in message.lower():
                    record['job_status'] = 'failed'
                elif 'job started' in message.lower():
                    record['job_status'] = 'started'
                
                # Extract error type if ERROR level
                if level == 'ERROR':
                    error_match = re.match(r'(\w+):', message)
                    if error_match:
                        record['error_type'] = error_match.group(1)
                
                # Extract key-value pairs
                for kv_match in kv_pattern.finditer(message):
                    key, value = kv_match.groups()
                    if key in ['duration_ms']:
                        try:
                            value = int(value)
                        except ValueError:
                            pass
                    record[key] = value
                
                records.append(record)
    
    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values('timestamp').reset_index(drop=True)
    return df


# =============================================================================
# CROSS-CORRELATION FUNCTIONS
# =============================================================================

def correlate_logs(web_df: pd.DataFrame, worker_df: pd.DataFrame) -> pd.DataFrame:
    """
    Join web and worker logs on request_id to find matching/missing entries.
    """
    # Filter to only rows with request_id
    web_with_req = web_df[web_df['request_id'].notna()].copy()
    worker_with_req = worker_df[worker_df['request_id'].notna()].copy()
    
    # Merge with outer join to capture all requests
    merged = pd.merge(
        web_with_req,
        worker_with_req,
        on='request_id',
        how='outer',
        suffixes=('_web', '_worker'),
        indicator=True
    )
    
    # Add correlation status
    merged['correlation_status'] = merged['_merge'].map({
        'both': 'matched',
        'left_only': 'web_only_no_worker',
        'right_only': 'worker_only_no_web'
    })
    
    return merged


def find_failed_requests(correlated_df: pd.DataFrame) -> pd.DataFrame:
    """
    Find requests that succeeded on web server but failed or never finished in worker.
    """
    # Requests in web but not in worker
    web_only = correlated_df[correlated_df['correlation_status'] == 'web_only_no_worker'].copy()
    return web_only


def find_worker_failures(worker_df: pd.DataFrame) -> pd.DataFrame:
    """
    Find all worker failures and errors.
    """
    failures = worker_df[
        (worker_df['level'] == 'ERROR') | 
        (worker_df['job_status'] == 'failed')
    ].copy()
    return failures


# =============================================================================
# AGGREGATION AND ANALYSIS FUNCTIONS
# =============================================================================

def aggregate_by_endpoint(web_df: pd.DataFrame) -> pd.DataFrame:
    """
    Group requests by endpoint (path) and calculate statistics.
    """
    if 'path' not in web_df.columns:
        return pd.DataFrame()
    
    # Normalize paths (remove specific IDs from paths like /product/12345)
    web_df = web_df.copy()
    web_df['normalized_path'] = web_df['path'].apply(
        lambda x: re.sub(r'/\d+', '/{id}', str(x)) if pd.notna(x) else x
    )
    
    agg = web_df.groupby('normalized_path').agg({
        'request_id': 'count',
        'status': lambda x: (x == 200).sum() if 'status' in web_df.columns else 0,
        'latency_ms': ['mean', 'max', 'min'] if 'latency_ms' in web_df.columns else 'count'
    }).reset_index()
    
    # Flatten column names
    agg.columns = ['_'.join(col).strip('_') if isinstance(col, tuple) else col 
                   for col in agg.columns]
    
    return agg


def aggregate_by_status(web_df: pd.DataFrame) -> pd.DataFrame:
    """
    Group requests by HTTP status code.
    """
    if 'status' not in web_df.columns:
        return pd.DataFrame()
    
    agg = web_df.groupby('status').agg({
        'request_id': 'count',
        'path': lambda x: x.value_counts().head(3).to_dict()
    }).reset_index()
    
    agg.columns = ['status', 'count', 'top_paths']
    return agg


def get_unique_affected_users(df: pd.DataFrame) -> List:
    """
    Get list of unique user_ids from a dataframe.
    """
    if 'user_id' in df.columns:
        return df['user_id'].dropna().unique().tolist()
    elif 'user_id_web' in df.columns:
        return df['user_id_web'].dropna().unique().tolist()
    return []


def analyze_time_distribution(df: pd.DataFrame, time_col: str = 'timestamp') -> pd.DataFrame:
    """
    Analyze distribution of events over time (by minute/hour).
    """
    if time_col not in df.columns and f'{time_col}_web' in df.columns:
        time_col = f'{time_col}_web'
    
    if time_col not in df.columns:
        return pd.DataFrame()
    
    df = df.copy()
    df['hour'] = df[time_col].dt.hour
    df['minute'] = df[time_col].dt.minute
    df['hour_minute'] = df[time_col].dt.strftime('%H:%M')
    
    hourly = df.groupby('hour').size().reset_index(name='count')
    return hourly


def find_incident_start(failed_df: pd.DataFrame, time_col: str = 'timestamp') -> Optional[datetime]:
    """
    Find the timestamp when failures started occurring.
    """
    if time_col not in failed_df.columns and f'{time_col}_web' in failed_df.columns:
        time_col = f'{time_col}_web'
    
    if failed_df.empty or time_col not in failed_df.columns:
        return None
    
    return failed_df[time_col].min()


# =============================================================================
# PATTERN DETECTION FUNCTIONS
# =============================================================================

def detect_common_patterns(failed_df: pd.DataFrame) -> Dict:
    """
    Analyze failed requests to find common patterns.
    """
    patterns = {
        'total_failures': len(failed_df),
        'by_status': {},
        'by_endpoint': {},
        'by_method': {},
        'by_hour': {},
        'common_error_messages': []
    }
    
    if failed_df.empty:
        return patterns
    
    # Status distribution
    status_col = 'status' if 'status' in failed_df.columns else 'status_web'
    if status_col in failed_df.columns:
        patterns['by_status'] = failed_df[status_col].value_counts().to_dict()
    
    # Endpoint distribution
    path_col = 'path' if 'path' in failed_df.columns else 'path_web'
    if path_col in failed_df.columns:
        # Normalize paths
        normalized = failed_df[path_col].apply(
            lambda x: re.sub(r'/\d+', '/{id}', str(x)) if pd.notna(x) else x
        )
        patterns['by_endpoint'] = normalized.value_counts().to_dict()
    
    # Method distribution
    method_col = 'method' if 'method' in failed_df.columns else 'method_web'
    if method_col in failed_df.columns:
        patterns['by_method'] = failed_df[method_col].value_counts().to_dict()
    
    # Time distribution
    time_col = 'timestamp' if 'timestamp' in failed_df.columns else 'timestamp_web'
    if time_col in failed_df.columns:
        patterns['by_hour'] = failed_df[time_col].dt.hour.value_counts().sort_index().to_dict()
    
    return patterns


def detect_error_burst(df: pd.DataFrame, time_col: str = 'timestamp', 
                       window_minutes: int = 5, threshold: int = 10) -> List[Dict]:
    """
    Detect time windows with high concentration of errors.
    """
    if df.empty or time_col not in df.columns:
        return []
    
    df = df.copy()
    df = df.sort_values(time_col)
    df['time_bucket'] = df[time_col].dt.floor(f'{window_minutes}min')
    
    counts = df.groupby('time_bucket').size()
    bursts = counts[counts >= threshold]
    
    return [{'time': str(t), 'count': c} for t, c in bursts.items()]


# =============================================================================
# REPORTING FUNCTIONS
# =============================================================================

def generate_summary_report(web_df: pd.DataFrame, worker_df: pd.DataFrame,
                           correlated_df: pd.DataFrame, failed_df: pd.DataFrame) -> str:
    """
    Generate a comprehensive text summary report.
    """
    report = []
    report.append("=" * 80)
    report.append("LOG FORENSIC ANALYSIS REPORT")
    report.append("=" * 80)
    report.append("")
    
    # Overview
    report.append("1. DATA OVERVIEW")
    report.append("-" * 40)
    report.append(f"   Total web.log entries: {len(web_df):,}")
    report.append(f"   Total worker.log entries: {len(worker_df):,}")
    
    if not web_df.empty:
        report.append(f"   Web log time range: {web_df['timestamp'].min()} to {web_df['timestamp'].max()}")
    if not worker_df.empty:
        report.append(f"   Worker log time range: {worker_df['timestamp'].min()} to {worker_df['timestamp'].max()}")
    report.append("")
    
    # Request correlation
    report.append("2. REQUEST CORRELATION ANALYSIS")
    report.append("-" * 40)
    if not correlated_df.empty:
        matched = len(correlated_df[correlated_df['correlation_status'] == 'matched'])
        web_only = len(correlated_df[correlated_df['correlation_status'] == 'web_only_no_worker'])
        worker_only = len(correlated_df[correlated_df['correlation_status'] == 'worker_only_no_web'])
        
        report.append(f"   Matched requests (web + worker): {matched:,}")
        report.append(f"   Web only (no worker completion): {web_only:,}")
        report.append(f"   Worker only (no web record): {worker_only:,}")
        
        if matched + web_only > 0:
            failure_rate = (web_only / (matched + web_only)) * 100
            report.append(f"   Failure rate (web requests without worker): {failure_rate:.2f}%")
    report.append("")
    
    # Failed requests analysis
    report.append("3. FAILED REQUESTS ANALYSIS")
    report.append("-" * 40)
    if not failed_df.empty:
        report.append(f"   Total failed/incomplete requests: {len(failed_df):,}")
        
        # Incident start time
        incident_start = find_incident_start(failed_df)
        if incident_start:
            report.append(f"   Incident start time: {incident_start}")
        
        # Affected users
        affected_users = get_unique_affected_users(failed_df)
        report.append(f"   Unique affected users: {len(affected_users):,}")
        
        # Patterns
        patterns = detect_common_patterns(failed_df)
        
        if patterns['by_status']:
            report.append(f"   Status code distribution:")
            for status, count in sorted(patterns['by_status'].items()):
                report.append(f"      - Status {status}: {count:,}")
        
        if patterns['by_endpoint']:
            report.append(f"   Endpoint distribution (top 10):")
            for endpoint, count in list(patterns['by_endpoint'].items())[:10]:
                report.append(f"      - {endpoint}: {count:,}")
        
        if patterns['by_method']:
            report.append(f"   HTTP method distribution:")
            for method, count in patterns['by_method'].items():
                report.append(f"      - {method}: {count:,}")
    else:
        report.append("   No failed requests found.")
    report.append("")
    
    # Worker errors
    report.append("4. WORKER ERROR ANALYSIS")
    report.append("-" * 40)
    worker_errors = worker_df[worker_df['level'] == 'ERROR']
    if not worker_errors.empty:
        report.append(f"   Total worker errors: {len(worker_errors):,}")
        
        if 'error_type' in worker_errors.columns:
            error_types = worker_errors['error_type'].value_counts()
            report.append("   Error types:")
            for error_type, count in error_types.items():
                report.append(f"      - {error_type}: {count:,}")
        
        if 'component' in worker_errors.columns:
            components = worker_errors['component'].value_counts()
            report.append("   By component:")
            for component, count in components.items():
                report.append(f"      - {component}: {count:,}")
    else:
        report.append("   No worker errors found.")
    report.append("")
    
    # Endpoint statistics
    report.append("5. ENDPOINT STATISTICS")
    report.append("-" * 40)
    endpoint_stats = aggregate_by_endpoint(web_df)
    if not endpoint_stats.empty:
        report.append("   Requests by endpoint:")
        for _, row in endpoint_stats.head(15).iterrows():
            path = row.get('normalized_path', 'unknown')
            count = row.get('request_id_count', row.get('request_id', 0))
            report.append(f"      - {path}: {count:,}")
    report.append("")
    
    # Status code distribution
    report.append("6. HTTP STATUS CODE DISTRIBUTION")
    report.append("-" * 40)
    if 'status' in web_df.columns:
        status_counts = web_df['status'].value_counts().sort_index()
        for status, count in status_counts.items():
            pct = (count / len(web_df)) * 100
            report.append(f"   Status {status}: {count:,} ({pct:.1f}%)")
    report.append("")
    
    # Time analysis
    report.append("7. TEMPORAL ANALYSIS")
    report.append("-" * 40)
    if not failed_df.empty:
        time_dist = analyze_time_distribution(failed_df)
        if not time_dist.empty:
            report.append("   Failed requests by hour:")
            for _, row in time_dist.iterrows():
                report.append(f"      Hour {int(row['hour']):02d}:00 - {int(row['count']):,} failures")
        
        # Error bursts
        time_col = 'timestamp' if 'timestamp' in failed_df.columns else 'timestamp_web'
        if time_col in failed_df.columns:
            bursts = detect_error_burst(failed_df, time_col)
            if bursts:
                report.append("   Error bursts detected (5-min windows with 10+ failures):")
                for burst in bursts[:10]:
                    report.append(f"      - {burst['time']}: {burst['count']} failures")
    report.append("")
    
    report.append("=" * 80)
    report.append("END OF REPORT")
    report.append("=" * 80)
    
    return "\n".join(report)


def export_to_csv(df: pd.DataFrame, filepath: str):
    """
    Export dataframe to CSV file.
    """
    df.to_csv(filepath, index=False)
    print(f"Exported to {filepath}")


# =============================================================================
# MAIN ANALYSIS FUNCTIONS
# =============================================================================

def run_full_analysis(web_log_path: str, worker_log_path: str, 
                      export_results: bool = True) -> Dict:
    """
    Run complete log analysis pipeline.
    """
    print("Starting log analysis...")
    print("-" * 50)
    
    # Parse logs
    print("Parsing web.log...")
    web_df = parse_web_log(web_log_path)
    print(f"   Parsed {len(web_df):,} entries")
    
    print("Parsing worker.log...")
    worker_df = parse_worker_log(worker_log_path)
    print(f"   Parsed {len(worker_df):,} entries")
    
    # Correlate
    print("Correlating logs by request_id...")
    correlated_df = correlate_logs(web_df, worker_df)
    
    # Find failures
    print("Identifying failed requests...")
    failed_df = find_failed_requests(correlated_df)
    print(f"   Found {len(failed_df):,} requests without worker completion")
    
    # Generate report
    print("Generating summary report...")
    report = generate_summary_report(web_df, worker_df, correlated_df, failed_df)
    print(report)
    
    # Export results if requested
    if export_results:
        print("\nExporting results...")
        
        # Export failed requests
        if not failed_df.empty:
            export_to_csv(failed_df, 'failed_requests.csv')
        
        # Export correlated data
        if not correlated_df.empty:
            export_to_csv(correlated_df, 'correlated_requests.csv')
        
        # Export worker errors
        worker_errors = worker_df[worker_df['level'] == 'ERROR']
        if not worker_errors.empty:
            export_to_csv(worker_errors, 'worker_errors.csv')
        
        # Save report
        with open('analysis_report.txt', 'w') as f:
            f.write(report)
        print("Saved report to analysis_report.txt")
    
    return {
        'web_df': web_df,
        'worker_df': worker_df,
        'correlated_df': correlated_df,
        'failed_df': failed_df,
        'report': report
    }


def analyze_async_requests(web_df: pd.DataFrame, worker_df: pd.DataFrame) -> Dict:
    """
    Specifically analyze async requests (status 202) that should have worker processing.
    These are the requests that NEED worker completion to be considered successful.
    """
    # Filter for 202 status (async/accepted requests)
    async_requests = web_df[web_df['status'] == 202].copy()
    
    # Get worker completions
    worker_completions = worker_df[worker_df['job_status'] == 'completed']['request_id'].tolist()
    worker_completions_set = set(worker_completions)
    
    # Find async requests without worker completion
    async_requests['has_worker_completion'] = async_requests['request_id'].isin(worker_completions_set)
    
    completed_async = async_requests[async_requests['has_worker_completion']]
    failed_async = async_requests[~async_requests['has_worker_completion']]
    
    return {
        'total_async_requests': len(async_requests),
        'completed_by_worker': len(completed_async),
        'failed_no_worker': len(failed_async),
        'failed_df': failed_async,
        'completion_rate': len(completed_async) / len(async_requests) * 100 if len(async_requests) > 0 else 0
    }


def find_incident_window(failed_df: pd.DataFrame, time_col: str = 'timestamp',
                         threshold_percentile: float = 90) -> Dict:
    """
    Find the time window where failures significantly increased (incident window).
    """
    if failed_df.empty or time_col not in failed_df.columns:
        return {}
    
    df = failed_df.copy()
    df['minute'] = df[time_col].dt.floor('1min')
    
    failures_per_minute = df.groupby('minute').size().reset_index(name='count')
    failures_per_minute = failures_per_minute.sort_values('minute')
    
    # Find when failures spike above baseline
    baseline = failures_per_minute['count'].quantile(0.25)
    threshold = failures_per_minute['count'].quantile(threshold_percentile / 100)
    
    # Find first spike
    spikes = failures_per_minute[failures_per_minute['count'] >= threshold]
    
    if spikes.empty:
        return {
            'baseline_failures_per_min': baseline,
            'threshold': threshold,
            'incident_start': None,
            'peak_time': None,
            'peak_count': None
        }
    
    return {
        'baseline_failures_per_min': baseline,
        'threshold': threshold,
        'incident_start': spikes['minute'].min(),
        'peak_time': failures_per_minute.loc[failures_per_minute['count'].idxmax(), 'minute'],
        'peak_count': failures_per_minute['count'].max()
    }


def analyze_worker_job_failures(worker_df: pd.DataFrame) -> pd.DataFrame:
    """
    Find worker job failures (not just errors, but actual job failures).
    """
    # Look for failed jobs
    job_failures = worker_df[
        (worker_df['job_status'] == 'failed') |
        ((worker_df['level'] == 'ERROR') & (worker_df['component'] == 'worker'))
    ].copy()
    return job_failures


def interactive_analysis(results: Dict):
    """
    Provide interactive analysis capabilities.
    """
    web_df = results['web_df']
    worker_df = results['worker_df']
    correlated_df = results['correlated_df']
    failed_df = results['failed_df']
    
    print("\n" + "=" * 80)
    print("DETAILED FORENSIC ANALYSIS")
    print("=" * 80)
    
    # Critical insight: Focus on ASYNC requests (202 status)
    print("\n" + "=" * 80)
    print("CRITICAL: ASYNC REQUEST ANALYSIS (Status 202)")
    print("=" * 80)
    print("Note: Status 202 (Accepted) indicates requests queued for async processing.")
    print("These requests REQUIRE worker completion to be successful.\n")
    
    async_analysis = analyze_async_requests(web_df, worker_df)
    print(f"Total async requests (202): {async_analysis['total_async_requests']:,}")
    print(f"Successfully processed by worker: {async_analysis['completed_by_worker']:,}")
    print(f"FAILED (no worker completion): {async_analysis['failed_no_worker']:,}")
    print(f"Worker completion rate: {async_analysis['completion_rate']:.2f}%")
    
    failed_async_df = async_analysis['failed_df']
    
    if not failed_async_df.empty:
        # Analyze failed async requests
        print("\n--- FAILED ASYNC REQUESTS BREAKDOWN ---")
        
        # By endpoint
        if 'path' in failed_async_df.columns:
            normalized = failed_async_df['path'].apply(
                lambda x: re.sub(r'/\d+', '/{id}', str(x)) if pd.notna(x) else x
            )
            endpoint_counts = normalized.value_counts()
            print("\nBy endpoint:")
            for endpoint, count in endpoint_counts.items():
                pct = (count / len(failed_async_df)) * 100
                print(f"   {endpoint}: {count:,} ({pct:.1f}%)")
        
        # Affected users
        if 'user_id' in failed_async_df.columns:
            unique_users = failed_async_df['user_id'].nunique()
            print(f"\nUnique users affected by async failures: {unique_users:,}")
        
        # First failure time
        print(f"\nFirst async failure: {failed_async_df['timestamp'].min()}")
        print(f"Last async failure: {failed_async_df['timestamp'].max()}")
    
    # Q1: When did the incident begin?
    print("\n" + "-" * 60)
    print("Q1: INCIDENT START TIME")
    print("-" * 60)
    
    # Check for failed async requests timing
    if not failed_async_df.empty:
        incident_window = find_incident_window(failed_async_df)
        print(f"First async failure: {failed_async_df['timestamp'].min()}")
        if incident_window.get('incident_start'):
            print(f"Incident spike started: {incident_window['incident_start']}")
        if incident_window.get('peak_time'):
            print(f"Peak failure time: {incident_window['peak_time']} ({incident_window['peak_count']} failures/min)")
    else:
        incident_start = find_incident_start(failed_df)
        if incident_start:
            print(f"First failure detected at: {incident_start}")
    
    # Q2: Which endpoints are failing?
    print("\n" + "-" * 60)
    print("Q2: FAILING ENDPOINTS")
    print("-" * 60)
    patterns = detect_common_patterns(failed_df)
    if patterns['by_endpoint']:
        print("Endpoints with failures (sorted by count):")
        sorted_endpoints = sorted(patterns['by_endpoint'].items(), 
                                  key=lambda x: x[1], reverse=True)
        for endpoint, count in sorted_endpoints[:10]:
            pct = (count / patterns['total_failures']) * 100
            print(f"   {endpoint}: {count:,} ({pct:.1f}%)")
    
    # Q3: How many users affected?
    print("\n" + "-" * 60)
    print("Q3: AFFECTED USERS")
    print("-" * 60)
    affected_users = get_unique_affected_users(failed_df)
    print(f"Total unique users affected: {len(affected_users):,}")
    if len(affected_users) <= 20:
        print(f"User IDs: {affected_users}")
    
    # Q4: Status codes in failures
    print("\n" + "-" * 60)
    print("Q4: STATUS CODES IN FAILED REQUESTS")
    print("-" * 60)
    if patterns['by_status']:
        print("HTTP status codes for requests without worker completion:")
        for status, count in sorted(patterns['by_status'].items()):
            pct = (count / patterns['total_failures']) * 100
            print(f"   Status {status}: {count:,} ({pct:.1f}%)")
    
    # Q5: Time distribution of failures
    print("\n" + "-" * 60)
    print("Q5: FAILURE TIME DISTRIBUTION")
    print("-" * 60)
    time_dist = analyze_time_distribution(failed_df)
    if not time_dist.empty:
        print("Failures by hour:")
        for _, row in time_dist.iterrows():
            print(f"   Hour {int(row['hour']):02d}:00 - {int(row['count']):,} failures")
    
    # Q6: Check for common patterns
    print("\n" + "-" * 60)
    print("Q6: COMMON PATTERNS IN FAILURES")
    print("-" * 60)
    if patterns['by_method']:
        print("By HTTP method:")
        for method, count in patterns['by_method'].items():
            pct = (count / patterns['total_failures']) * 100
            print(f"   {method}: {count:,} ({pct:.1f}%)")
    
    # Check if 100% of failures share a specific trait
    print("\nChecking for 100% common traits:")
    for trait, counts in [('status', patterns['by_status']), 
                          ('method', patterns['by_method']),
                          ('endpoint', patterns['by_endpoint'])]:
        if counts:
            max_val = max(counts, key=counts.get)
            max_count = counts[max_val]
            pct = (max_count / patterns['total_failures']) * 100
            if pct == 100:
                print(f"   ALL failures have {trait}={max_val}")
            elif pct >= 90:
                print(f"   {pct:.1f}% of failures have {trait}={max_val}")
    
    # Worker error analysis
    print("\n" + "-" * 60)
    print("Q7: WORKER ERROR ANALYSIS")
    print("-" * 60)
    
    worker_job_failures = analyze_worker_job_failures(worker_df)
    if not worker_job_failures.empty:
        print(f"Total worker job failures/errors: {len(worker_job_failures):,}")
        
        if 'error_type' in worker_job_failures.columns:
            error_types = worker_job_failures['error_type'].value_counts()
            print("\nError types:")
            for etype, count in error_types.head(10).items():
                print(f"   {etype}: {count:,}")
        
        # Check for error messages
        if 'raw_message' in worker_job_failures.columns:
            print("\nSample error messages:")
            for msg in worker_job_failures['raw_message'].head(5):
                print(f"   - {msg[:100]}...")
    
    # Summary statistics
    print("\n" + "=" * 80)
    print("EXECUTIVE SUMMARY")
    print("=" * 80)
    
    total_requests = len(web_df)
    total_failures = len(failed_df)
    
    print(f"\nTotal web requests analyzed: {total_requests:,}")
    print(f"Total requests missing worker processing: {total_failures:,}")
    print(f"Overall failure rate: {(total_failures/total_requests)*100:.2f}%")
    
    if async_analysis['total_async_requests'] > 0:
        print(f"\nAsync requests (202 - critical path):")
        print(f"   Total: {async_analysis['total_async_requests']:,}")
        print(f"   Failed: {async_analysis['failed_no_worker']:,}")
        print(f"   Failure rate: {100 - async_analysis['completion_rate']:.2f}%")
    
    print(f"\nUnique users impacted: {len(affected_users):,}")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Log Forensic Analysis Tool')
    parser.add_argument('--web-log', default='web.log', 
                        help='Path to web.log file')
    parser.add_argument('--worker-log', default='worker.log', 
                        help='Path to worker.log file')
    parser.add_argument('--no-export', action='store_true',
                        help='Skip exporting CSV files')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Run interactive analysis after main report')
    
    args = parser.parse_args()
    
    # Run analysis
    results = run_full_analysis(
        args.web_log, 
        args.worker_log,
        export_results=not args.no_export
    )
    
    # Run interactive analysis if requested
    if args.interactive:
        interactive_analysis(results)
    
    print("\nAnalysis complete!")
    
```

## Investigation Process
1. First I examined the structure of both logs file to understand what details does each log contain.
2. Wrote a Python script using regex and pandas to extract key value pairs to convert the unstructured data into structured data for better visual understanding.
3. request_id was common for logs across web.log and worker.log, so I used it to cross correlate logs. By correlating, I got web requests and their corresponding worker log.
4. I got two types of error in the files.
5. Investigated metric-worker error but it turned out that it was not related to the problem. Then i analysed another worker-error which was related to our real problem.
6. Sorted the failed checkout requests in the csv file to get the first occurrence of failing request.
7. After examining the worker errors, I noticed that all failing requests are using same shared resource and same error signature. 
8. Extracted distinct user_id from failed requests