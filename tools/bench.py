#!/usr/bin/env python3
"""
bench.py - Statistical analysis tool for soliton.c benchmark results

Computes median, σ, p95, p99 from CSV benchmark data.
Detects variance > 5% and warns.

Usage:
    python tools/bench.py results/evp_benchmark.csv
    python tools/bench.py results/evp_benchmark.csv --format table
    python tools/bench.py results/evp_benchmark.csv --format csv
"""

import sys
import csv
import statistics
from collections import defaultdict
from typing import List, Dict, Tuple

def parse_csv(filepath: str) -> Tuple[Dict, List[Dict]]:
    """Parse CSV file, extracting metadata and data rows."""
    metadata = {}
    data_rows = []

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Parse metadata (comments starting with #)
            if line.startswith('#'):
                if ':' in line:
                    key, value = line[1:].split(':', 1)
                    metadata[key.strip()] = value.strip()
                continue

            # Parse data rows
            if line and not line.startswith('#'):
                reader = csv.DictReader([line], fieldnames=['size', 'cycles', 'cpb'])
                for row in reader:
                    try:
                        data_rows.append({
                            'size': int(row['size']),
                            'cycles': float(row['cycles']),
                            'cpb': float(row['cpb'])
                        })
                    except (ValueError, KeyError):
                        # Skip malformed rows
                        continue

    return metadata, data_rows

def compute_stats(values: List[float]) -> Dict[str, float]:
    """Compute statistical metrics for a list of values."""
    if not values:
        return {}

    sorted_values = sorted(values)
    n = len(sorted_values)

    return {
        'count': n,
        'median': statistics.median(sorted_values),
        'mean': statistics.mean(sorted_values),
        'stdev': statistics.stdev(sorted_values) if n > 1 else 0.0,
        'min': sorted_values[0],
        'max': sorted_values[-1],
        'p95': sorted_values[int(n * 0.95)] if n > 1 else sorted_values[0],
        'p99': sorted_values[int(n * 0.99)] if n > 1 else sorted_values[0],
    }

def analyze_benchmarks(data_rows: List[Dict]) -> Dict[int, Dict]:
    """Group data by message size and compute statistics."""
    grouped = defaultdict(lambda: {'cycles': [], 'cpb': []})

    for row in data_rows:
        size = row['size']
        grouped[size]['cycles'].append(row['cycles'])
        grouped[size]['cpb'].append(row['cpb'])

    results = {}
    for size, metrics in grouped.items():
        results[size] = {
            'cycles': compute_stats(metrics['cycles']),
            'cpb': compute_stats(metrics['cpb'])
        }

    return results

def format_table(results: Dict[int, Dict], metadata: Dict) -> str:
    """Format results as a human-readable table."""
    output = []

    # Header
    output.append("=" * 80)
    output.append("Benchmark Statistical Analysis")
    output.append("=" * 80)
    output.append("")

    # Metadata
    if metadata:
        output.append("Metadata:")
        for key, value in metadata.items():
            output.append(f"  {key}: {value}")
        output.append("")

    # Results table
    output.append(f"{'Size':<10} {'Metric':<8} {'Median':<12} {'σ':<12} {'%CV':<8} {'p95':<12} {'p99':<12} {'Status':<10}")
    output.append("-" * 80)

    for size in sorted(results.keys()):
        cpb_stats = results[size]['cpb']

        median = cpb_stats['median']
        stdev = cpb_stats['stdev']
        cv = (stdev / median * 100) if median > 0 else 0
        p95 = cpb_stats['p95']
        p99 = cpb_stats['p99']

        # Variance check
        status = "OK" if cv < 5.0 else "WARN"
        status_symbol = "✓" if cv < 5.0 else "⚠"

        output.append(
            f"{size:<10} {'cpb':<8} {median:<12.4f} {stdev:<12.6f} {cv:<8.2f} "
            f"{p95:<12.4f} {p99:<12.4f} {status_symbol} {status:<8}"
        )

    output.append("")
    output.append("Legend:")
    output.append("  Median: 50th percentile (target metric)")
    output.append("  σ: Standard deviation (repeatability)")
    output.append("  %CV: Coefficient of variation (σ/median × 100)")
    output.append("  p95/p99: 95th/99th percentile latency")
    output.append("  Status: OK if %CV < 5%, WARN otherwise")
    output.append("")

    # Summary
    all_cv = [
        (results[size]['cpb']['stdev'] / results[size]['cpb']['median'] * 100)
        for size in results
        if results[size]['cpb']['median'] > 0
    ]

    max_cv = max(all_cv) if all_cv else 0
    all_ok = max_cv < 5.0

    output.append(f"Overall Status: {'PASS ✓' if all_ok else 'FAIL ⚠ (variance too high)'}")
    output.append(f"Max %CV: {max_cv:.2f}% (threshold: <5%)")

    if not all_ok:
        output.append("")
        output.append("⚠ WARNING: Variance exceeds 5% threshold!")
        output.append("  Recommendations:")
        output.append("  - Disable CPU turbo boost")
        output.append("  - Set CPU governor to 'performance'")
        output.append("  - Ensure no background processes")
        output.append("  - Allow system to cool between runs")

    output.append("=" * 80)

    return "\n".join(output)

def format_csv_output(results: Dict[int, Dict]) -> str:
    """Format results as CSV for further processing."""
    output = []
    output.append("size,median_cpb,stdev_cpb,cv_percent,p95_cpb,p99_cpb,count")

    for size in sorted(results.keys()):
        cpb_stats = results[size]['cpb']
        median = cpb_stats['median']
        stdev = cpb_stats['stdev']
        cv = (stdev / median * 100) if median > 0 else 0

        output.append(
            f"{size},{median:.6f},{stdev:.6f},{cv:.4f},"
            f"{cpb_stats['p95']:.6f},{cpb_stats['p99']:.6f},{int(cpb_stats['count'])}"
        )

    return "\n".join(output)

def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/bench.py <csv_file> [--format table|csv]", file=sys.stderr)
        print("", file=sys.stderr)
        print("Examples:", file=sys.stderr)
        print("  python tools/bench.py results/evp_benchmark.csv", file=sys.stderr)
        print("  python tools/bench.py results/evp_benchmark.csv --format csv", file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]
    output_format = 'table'

    if len(sys.argv) > 2 and sys.argv[2] == '--format':
        output_format = sys.argv[3] if len(sys.argv) > 3 else 'table'

    try:
        metadata, data_rows = parse_csv(filepath)

        if not data_rows:
            print(f"Error: No valid data rows found in {filepath}", file=sys.stderr)
            sys.exit(1)

        results = analyze_benchmarks(data_rows)

        if output_format == 'csv':
            print(format_csv_output(results))
        else:
            print(format_table(results, metadata))

        # Exit code based on variance check
        all_cv = [
            (results[size]['cpb']['stdev'] / results[size]['cpb']['median'] * 100)
            for size in results
            if results[size]['cpb']['median'] > 0
        ]
        max_cv = max(all_cv) if all_cv else 0

        sys.exit(0 if max_cv < 5.0 else 1)

    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
