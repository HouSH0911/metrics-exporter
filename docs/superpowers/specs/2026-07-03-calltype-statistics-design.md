# Call Type Statistics with 5-Minute Time Window Design

## Overview

在现有文件传输统计（StreamStat）基础上，新增按话单类型 × 5分钟时间点的细粒度统计，支持可配置的最近 N 分钟时间窗口，同时在 JSON 和 Prometheus 两种格式中输出。

## Configuration

`config.json` 中 `fileTransfer` 段新增 `recentMinutes` 字段：

```json
{
    "fileTransfer": {
        "logPath": "/home/haohan/importer/logs/statistic/",
        "streams": ["XDR_SJJS", "XDR_JK"],
        "recentMinutes": 60
    }
}
```

- `recentMinutes`：时间窗口大小，单位分钟。统计 `now - recentMinutes` 到 `now` 之间的5分点数据。未配置时默认 0（不启用新统计）。

## Data Source

- 统计文件路径：`{logPath}/SFTPOutput.fileLog.stat`（当天）、`{logPath}/SFTPOutput.fileLog.stat.YYYYMMDD`（历史日期）
- 文件格式：pipe(`|`)分隔，共 14 个字段
  - 字段索引 1：数据流名称（如 `XDR_JK`、`XDR_SJJS`）
  - 字段索引 3：文件绝对路径（如 `/home/xDR/log/20260702/100_20260703000011_083.csv`）
  - 字段索引 4：文件大小（字节）
  - 最后一个字段：状态（`0`=成功）

## Extraction Rules

从字段 3（文件路径）的文件名部分提取：

| 提取项 | 文件名位置 (以 `_` 分隔) | 规则 | 示例 (`100_20260703000011_083.csv`) |
|--------|--------------------------|------|-------------------------------------|
| 话单类型 (callType) | 第 1 段 | 直接取 | `100` |
| 5分钟时间点 (timePoint) | 第 2 段 | 取前 12 位 `YYYYMMDDHHMM`，其中分钟为 5 的倍数 | `202607030000` |

## Time Window Logic

- 计算窗口：`[now - recentMinutes, now]`
- 仅统计 `timePoint` 落入窗口内的记录
- 跨天场景：若窗口跨越午夜，自动同时读取当天文件和前一天/历史日期文件，合并处理
- 文件不存在时忽略，不报错

## Data Structures

### New Struct

```go
type CallTypeStat struct {
    StreamName string `json:"streamName"`
    CallType   string `json:"callType"`
    TimePoint  string `json:"timePoint"`
    TotalFiles int64  `json:"totalFiles"`
    TotalSize  int64  `json:"totalSize"`
}
```

### Modified Structs

```go
type FileTransferConfig struct {
    LogPath       string   `json:"logPath"`
    Streams       []string `json:"streams"`
    RecentMinutes int      `json:"recentMinutes"` // 新增
}

type StatusResponse struct {
    // ... existing fields unchanged
    CallTypeStats []CallTypeStat `json:"callTypeStats"` // 新增
}
```

### Cache Addition

```go
cache.CallTypeStats []CallTypeStat // 新增缓存字段
```

## Output Formats

### JSON (`/check`)

`callTypeStats` 新增字段，与现有 `streamStats` 并存：

```json
{
    "streamStats": [...],
    "callTypeStats": [
        {"streamName":"XDR_JK","callType":"100","timePoint":"202607030000","totalFiles":5,"totalSize":1048576000}
    ]
}
```

### Prometheus (`/metrics`)

新增两个指标：

```
# HELP server_calltype_files_total Call type file count in recent time window.
# TYPE server_calltype_files_total gauge
server_calltype_files_total{instance="...",type="stream",streamName="XDR_JK",callType="100",timePoint="202607030000"} 5

# HELP server_calltype_size_bytes_total Call type total size in bytes in recent time window.
# TYPE server_calltype_size_bytes_total gauge
server_calltype_size_bytes_total{instance="...",type="stream",streamName="XDR_JK",callType="100",timePoint="202607030000"} 1048576000
```

## Files to Modify

| File | Changes |
|------|---------|
| `struct_v1.6.go` | Add `CallTypeStat` struct; add `RecentMinutes` to `FileTransferConfig`; add `CallTypeStats` to `StatusResponse` and cache |
| `sup_func_v1.6.go` | Add `collectCallTypeStats()` function; call it in `doCollectMetrics()` |
| `json_handle_v1.6.go` | Include `callTypeStats` in JSON response |
| `prometheus_v1.6.go` | Output two new Prometheus metrics |

## Key Implementation Details

- `collectCallTypeStats()` 复用现有 `collectTransferStats()` 的文件读取模式
- 时间点比较：将 `timePoint` 字符串 (`YYYYMMDDHHMM`) 解析为 `time.Time` 进行比较
- 状态类记录（status != "0"）不纳入统计
- 仅统计配置的 `streams` 中的数据流
- 统计结果按 `(streamName, callType, timePoint)` 三元组聚合（累加文件数和大小）
- 刷新频率复用已有的 `transferStatInterval`（30 秒）
