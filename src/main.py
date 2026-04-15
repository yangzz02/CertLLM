#!/usr/bin/env python3
"""
Main entry point for CertLLM Attribution Pipeline

Usage:
    # Full pipeline from IP list
    python src/main.py --mode scan --input data/target_ip.txt --output output/result.csv

    # Step-by-step: Stage 0 (active scan only)
    python src/main.py --mode stage0 --input data/target_ip.txt --output output/intermediate/scan.jsonl

    # Step-by-step: Stage 1 (cert validation only)
    python src/main.py --mode stage1 --input output/intermediate/scan.jsonl --output output/intermediate/stage1.jsonl

    # Step-by-step: Stage 2A (HTML fetching only)
    python src/main.py --mode stage2a --input output/intermediate/stage1.jsonl --output output/intermediate/stage2a.jsonl

    # Step-by-step: Stage 2B (LLM analysis only)
    python src/main.py --mode stage2b --input output/intermediate/stage2a.jsonl --output output/result.jsonl --csv output/result.csv

    # Step-by-step: Stage 1 + 2A + 2B (from existing scan)
    python src/main.py --mode pipeline --input output/intermediate/scan.jsonl --output output/result.jsonl --csv output/result.csv
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pipeline import AttributionPipeline


def main():
    parser = argparse.ArgumentParser(
        description='CertLLM - TLS Certificate-based IP Attribution Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline from IP list
  python src/main.py --mode scan --input ips.txt --output output/result.csv

  # Stage 0: Scan IPs with zgrab2
  python src/main.py --mode stage0 --input ips.txt --output output/intermediate/scan.jsonl

  # Stage 1: Certificate validation
  python src/main.py --mode stage1 --input scan.jsonl --output stage1.jsonl

  # Stage 2A: HTML fetching
  python src/main.py --mode stage2a --input stage1.jsonl --output stage2a.jsonl

  # Stage 2B: LLM analysis
  python src/main.py --mode stage2b --input stage2a.jsonl --output result.jsonl --csv result.csv

  # Pipeline from existing scan results (Stage 1→2A→2B)
  python src/main.py --mode pipeline --input scan.jsonl --output result.jsonl --csv result.csv
        """
    )

    parser.add_argument('--mode', '-m',
                        choices=['scan', 'stage0', 'stage1', 'stage2a', 'stage2b', 'pipeline'],
                        default='scan',
                        help="""Pipeline execution mode:
  scan     - Full pipeline from IP list (Stage 0→1→2A→2B)
  stage0   - Active scan only (IP list → zgrab2 JSONL)
  stage1   - Certificate validation only
  stage2a  - HTML fetching only
  stage2b  - LLM analysis only
  pipeline - Stage 1→2A→2B from existing scan results
  (default: scan)""")

    parser.add_argument('--input', '-i',
                        required=True,
                        help='Input file path. IP list for stage0/scan; JSONL for other modes.')

    parser.add_argument('--output', '-o',
                        required=True,
                        help='Output file path (JSONL).')

    parser.add_argument('--csv',
                        default=None,
                        help='Optional CSV output path (ip,org format). Used with scan/stage2b/pipeline modes.')

    parser.add_argument('--concurrency', '-c',
                        type=int,
                        default=500,
                        help='zgrab2 concurrent connections for Stage 0 (default: 500).')

    parser.add_argument('--workers', '-w',
                        type=int,
                        default=10,
                        help='LLM concurrent workers for Stage 2B (default: 10).')

    args = parser.parse_args()

    # Create pipeline
    pipeline = AttributionPipeline()

    if args.mode == 'scan':
        # Full pipeline: IP list → Stage 0 → 1 → 2A → 2B
        print("=" * 80)
        print("Mode: Full Pipeline (IP List → Stage 0 → 1 → 2A → 2B)")
        print("=" * 80)
        stats = pipeline.process_from_ip_list(
            ip_file=args.input,
            output_jsonl=args.output,
            output_csv=args.csv,
            scan_concurrency=args.concurrency
        )

    elif args.mode == 'stage0':
        # Stage 0 only: Active scan
        print("=" * 80)
        print("Mode: Stage 0 - Active Scanning")
        print("=" * 80)
        pipeline.stage_0_active_scan(
            ip_file=args.input,
            output_jsonl=args.output,
            concurrency=args.concurrency
        )

    elif args.mode == 'stage1':
        # Stage 1 only: Certificate validation
        print("=" * 80)
        print("Mode: Stage 1 - Certificate Validation")
        print("=" * 80)
        stats = pipeline.process_file(
            input_file=args.input,
            output_jsonl=args.output,
            stop_at_stage1=True
        )

    elif args.mode == 'stage2a':
        # Stage 2A only: HTML fetching
        print("=" * 80)
        print("Mode: Stage 2A - HTML Fetching")
        print("=" * 80)
        stats = pipeline.process_stage2a_from_stage1(
            intermediate_file=args.input,
            output_jsonl=args.output
        )

    elif args.mode == 'stage2b':
        # Stage 2B only: LLM analysis
        print("=" * 80)
        print("Mode: Stage 2B - LLM Analysis")
        print("=" * 80)
        stats = pipeline.process_stage2b_from_stage2a(
            stage2a_file=args.input,
            output_jsonl=args.output,
            output_csv=args.csv,
            max_workers=args.workers
        )

    elif args.mode == 'pipeline':
        # Stage 1 → 2A → 2B from existing scan results
        print("=" * 80)
        print("Mode: Pipeline (Stage 1 → 2A → 2B)")
        print("=" * 80)
        stats = pipeline.process_file(
            input_file=args.input,
            output_jsonl=args.output,
        )
        # Save CSV if requested
        if args.csv:
            csv_path = Path(args.csv)
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            with open(csv_path, 'w', newline='') as f:
                import csv as csv_mod
                writer = csv_mod.writer(f)
                writer.writerow(['ip', 'org'])
                with open(args.output, 'r') as fin:
                    for line in fin:
                        if not line.strip():
                            continue
                        d = json.loads(line)
                        writer.writerow([d.get('ip', ''), d.get('org', 'unknown')])
            print(f"  CSV saved to: {args.csv}")


if __name__ == '__main__':
    main()
