# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based metrics exporter service that monitors system resources, processes, directories, network ports, and file transfers. It exposes metrics via HTTP endpoint on port 9600 and can be installed as a system service on Linux (supports both systemd and SysVinit for CentOS 6/7+).

## Build and Run

**Build the binary:**
```bash
go build -o metrics-exporter metrics-v1.4.go service.go
```

**Cross-compile for Linux x86:**
```bash
GOOS=linux GOARCH=386 go build -o metrics-exporter metrics-v1.4.go service.go
```

**Run directly:**
```bash
./metrics-exporter
```

**Install as service:**
```bash
./metrics-exporter -i
```

**Upgrade service:**
```bash
./metrics-exporter -u
```

**Service management (systemd):**
```bash
systemctl start metrics-exporter
systemctl stop metrics-exporter
systemctl status metrics-exporter
```

**Service management (SysVinit/CentOS 6):**
```bash
service metrics-exporter start
service metrics-exporter stop
service metrics-exporter status
```

## Architecture

### Main Components

**metrics-v1.4.go** - Core monitoring logic with the following key features:
- Background collector that runs every 3 seconds to gather CPU, memory, disk, and process metrics
- EMA (Exponential Moving Average) smoothing for CPU metrics to reduce noise
- 30-second cache TTL for HTTP responses to reduce load
- File transfer statistics collection (refreshed every 5 minutes)
- Time-range based directory monitoring (allows monitoring specific time windows)
- Port connectivity checks to remote targets
- HTTP server on port 9600 with `/check` endpoint

**service.go** - Service management and configuration:
- Service installation/upgrade logic for both systemd and SysVinit
- Configuration file loading and hot-reloading via fsnotify
- Automatic detection of CentOS 6 vs 7+ for appropriate service type

### Configuration

The service reads `config.json` from the same directory as the executable. Configuration changes are automatically detected and reloaded without service restart.

**Configuration structure:**
- `baseDirs`: Directories to monitor with optional time ranges (HH:MM format, supports cross-midnight ranges)
- `processes`: Process names to check (supports substring matching)
- `targets`: Remote hosts and ports to check connectivity
- `fileTransfer`: File transfer log monitoring configuration (v1.4 feature)

### Key Design Patterns

**Background Collection**: Metrics are collected in a background goroutine every 3 seconds, avoiding blocking HTTP requests. The `/check` endpoint returns cached data.

**Cache Strategy**:
- CPU/Memory/Process: 3-second refresh cycle
- Disk partitions: 5-minute refresh cycle (expensive operation)
- File transfer stats: 5-minute refresh cycle (files generated daily)
- HTTP cache TTL: 30 seconds

**Concurrency Safety**: All shared state uses `sync.RWMutex` for thread-safe reads/writes.

**Directory Monitoring Logic**:
- Checks for date-based folders (YYYYMMDD format)
- Looks for files with 5-minute interval timestamps (HHMM rounded to nearest 5)
- Falls back to checking 70 minutes ago if current folder doesn't exist
- Respects time range configuration for conditional monitoring

**File Transfer Monitoring** (v1.4):
- Parses `SFTPOutput.fileLog.stat.YYYYMMDD` files from previous day
- Extracts success count and total size per data stream
- Format: pipe-delimited with 12 fields, status in last field (0=success)

## Version History

- **v0.1**: Combined server and directory monitoring into single program
- **v0.2**: Added config file hot-reloading
- **v1.0**: Added port connectivity monitoring
- **v1.1**: Added 30-second cache mechanism to reduce CPU usage
- **v1.4**: Added daily file transfer statistics monitoring

## Important Notes

- The service runs on port 9600 and expects to be accessible for monitoring queries
- Process detection uses gopsutil and supports both exact name matching and substring matching in command lines
- Memory calculation excludes buffers and cached memory on Linux for more accurate "used" percentage
- The executable must be in the same directory as config.json for proper operation
- Backup versions are stored in `bak/` directory organized by version number
