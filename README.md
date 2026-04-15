# CertLLM

**CertLLM**: Certificate-Grounded LLM Inference for Accurate Internet Asset Attribution

## Overview

CertLLM is a practical Internet asset attribution framework that leverages certificate-grounded evidence and large language model (LLM)-assisted semantic inference.

### Key Features

- **Active Scanning**: Scan target IP lists directly using zgrab2 (no pre-existing scan data required)
- **Multi-stage Pipeline**: Modular Stage 0→1→2A→2B architecture with intermediate result persistence
- **Certificate Analysis**: Extract and validate TLS certificates to identify OV/EV organization fields
- **LLM-enhanced Attribution**: Use LLMs to analyze HTML content for DV certificates that lack organization information
- **IPv4 & IPv6 Support**: Full dual-stack support
- **Multiple LLM Backends**: Compatible with OpenAI, DeepSeek, Anthropic Claude, and other OpenAI-compatible APIs

### Early Termination Logic 

1. **Untrusted certificate** → `org = unknown` → STOP
2. **CDN/Cloud detected** (via ASN + headers) → `org = unknown` → STOP
3. **Certificate contains organization** (OV/EV) → `org = cert_org` → STOP
4. **DV certificate** (no org field) → proceed to Stage 2

## Installation

### Prerequisites

- Python 3.9+
- [zgrab2](https://github.com/zmap/zgrab2) binary (place in `utils/zgrab2`)

### Setup

```bash

# Install dependencies
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env with your LLM API credentials
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key for LLM service | `sk-...` |
| `OPENAI_BASE_URL` | API base URL (supports OpenAI-compatible services) | `https://api.openai.com/v1` |
| `OPENAI_MODEL` | Default model to use | `gpt-4o`, `deepseek-v3.2` |

## Usage

### CLI (Recommended)

```bash
# Full pipeline: IP list → Stage 0 → 1 → 2A → 2B → CSV
python src/main.py --mode scan --input data/target_ip.txt --output output/result.jsonl --csv output/result.csv

# Step-by-step mode:
# Stage 0: Scan IPs with zgrab2
python src/main.py --mode stage0 --input data/target_ip.txt --output output/intermediate/scan.jsonl

# Stage 1: Certificate validation
python src/main.py --mode stage1 --input output/intermediate/scan.jsonl --output output/intermediate/stage1.jsonl

# Stage 2A: HTML fetching
python src/main.py --mode stage2a --input output/intermediate/stage1.jsonl --output output/intermediate/stage2a.jsonl

# Stage 2B: LLM analysis
python src/main.py --mode stage2b --input output/intermediate/stage2a.jsonl --output output/result.jsonl --csv output/result.csv

# Pipeline from existing scan results (Stage 1 → 2A → 2B)
python src/main.py --mode pipeline --input output/intermediate/scan.jsonl --output output/result.jsonl --csv output/result.csv
```

### CLI Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--mode` | `-m` | Execution mode (see below) | `scan` |
| `--input` | `-i` | Input file path (required) | — |
| `--output` | `-o` | Output JSONL path (required) | — |
| `--csv` | | Optional CSV output path (ip,org) | — |
| `--concurrency` | `-c` | zgrab2 concurrent connections (Stage 0) | `500` |
| `--workers` | `-w` | LLM concurrent workers (Stage 2B) | `10` |

### Execution Modes

| Mode | Stages | Input | Description |
|------|--------|-------|-------------|
| `scan` | 0→1→2A→2B | IP list | Full pipeline from IP list |
| `stage0` | 0 | IP list | Active scan only |
| `stage1` | 1 | zgrab2 JSONL | Certificate validation only |
| `stage2a` | 2A | Stage 1 JSONL | HTML fetching only |
| `stage2b` | 2B | Stage 2A JSONL | LLM analysis only |
| `pipeline` | 1→2A→2B | zgrab2 JSONL | Full pipeline from existing scan |


### IP List File Format

One IP address per line. Supports IPv4 and IPv6. Lines starting with `#` are comments.

```
# Production servers
142.250.189.238
20.190.151.7

# IPv6
2408:8752:e00:a13:103::3
2603:1047:1:198::3
```


