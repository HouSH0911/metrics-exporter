# Prometheus Metrics Endpoint Design

## Overview

新增 `/metrics` 端点，以 Prometheus text 格式输出监控数据。原有 `/check` 端点保持不变，JSON 格式完全向后兼容。

## Endpoints

| Endpoint | Format | Content-Type | Description |
|----------|--------|-------------|-------------|
| `/check` | JSON | `application/json` | 保持不变，原有调用方不受影响 |
| `/metrics` | Prometheus text | `text/plain; version=0.0.4` | 新增，供 Prometheus 抓取 |

## Configuration

`config.json` 新增字段：

```json
{
    "instance": "server-01",
    ...
}
```

- `instance`：本机标识，作为 Prometheus 所有指标的 `instance` 标签值
- 未配置时自动 fallback 到 `os.Hostname()`

## Prometheus Metric Design

### Naming Convention

- 前缀：`server_`
- 分隔符：`_`（snake_case）
- 所有指标均为 `gauge` 类型

### Common Labels

所有指标都带有两个基础标签：

| Label | Description |
|-------|-------------|
| `instance` | 服务器地址标识，来自 config.json 或 os.Hostname() |
| `type` | 指标类型分类：`cpu`, `memory`, `disk`, `directory`, `process`, `port`, `stream` |

### Metrics

#### System Metrics (Gauge, actual values)

```
server_cpu_usage_percent{instance="...",type="cpu"} <float64>
server_memory_usage_percent{instance="...",type="memory"} <float64>
server_disk_usage_percent{instance="...",type="disk",mountpoint="..."} <float64>
```

#### Status Metrics (Gauge, always value=1, differentiated by status label)

```
server_directory_exists{instance="...",type="directory",baseDir="...",status="exist|noexist"} 1
server_xdrfile_exists{instance="...",type="directory",baseDir="...",status="exist|noexist"} 1
server_process_running{instance="...",type="process",processName="...",status="up|down"} 1
server_port_reachable{instance="...",type="port",host="...",port="...",status="up|down"} 1
```

status label values:
- directory/file: `exist` / `noexist`
- process/port: `up` / `down`

#### Stream Statistics (Gauge)

```
server_stream_total_files{instance="...",type="stream",streamName="...",statDate="..."} <int64>
server_stream_total_size_bytes{instance="...",type="stream",streamName="...",statDate="..."} <int64>
```

## Implementation Plan

### Files to modify

1. **struct_v1.5.go**: Config struct add `Instance` field
2. **handle_v1.5.go**: Add `metricsHandler()` function + helper `formatPrometheus()` / `escapeLabelValue()`
3. **main_v1.5.go**: Register `/metrics` route
4. **config.json**: Add `instance` field example

### Key Implementation Details

- `/metrics` handler reuses cached data from background collector (no additional system load)
- Helper functions: `formatPrometheus()` for generating text output, `escapeLabelValue()` for escaping special characters in label values
- Status metrics always output, with `status` label indicating the state
- Metric value is always 1 for status metrics (info-style gauge)
