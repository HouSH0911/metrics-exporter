# Call Type Statistics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-calltype × 5-minute-timepoint statistics within a configurable recent time window to both JSON and Prometheus output.

**Architecture:** New `CallTypeStat` struct added to cache and response models. New `collectCallTypeStats()` function parses stat files, extracts call type and time point from file paths, filters by time window, and aggregates. Results flow through existing handler → JSON / metricsHandler → Prometheus paths.

**Tech Stack:** Go 1.24, gopsutil, fsnotify

## Global Constraints

- `recentMinutes` defaults to 0 (feature disabled when not configured)
- Time window: `[now - recentMinutes, now]`
- Cross-midnight: read today + yesterday stat files, merge results
- Only count records with status "0" (success)
- Only process configured `streams` list
- Refresh interval: 30 seconds (reuse existing `transferStatInterval`)

---

### Task 1: Add data structures to struct_v1.6.go

**Files:**
- Modify: `struct_v1.6.go`

**Interfaces:**
- Produces: `CallTypeStat` struct, updated `FileTransferConfig`, updated `StatusResponse`, updated cache anonymous struct

- [ ] **Step 1: Add CallTypeStat struct after StreamStat**

```go
// v1.6新增：话单类型统计（按数据流+话单类型+5分钟时间点维度）
type CallTypeStat struct {
    StreamName string `json:"streamName"` // 数据流名称，如 XDR_JK
    CallType   string `json:"callType"`   // 话单类型，如 100、106
    TimePoint  string `json:"timePoint"`  // 5分钟时间点，如 202607030000
    TotalFiles int64  `json:"totalFiles"` // 成功传输的文件数
    TotalSize  int64  `json:"totalSize"`  // 成功传输的文件总大小(字节)
}
```

- [ ] **Step 2: Add RecentMinutes to FileTransferConfig**

```go
type FileTransferConfig struct {
    LogPath       string   `json:"logPath"`
    Streams       []string `json:"streams"`
    RecentMinutes int      `json:"recentMinutes"` // 新增：最近N分钟的5分点统计窗口
}
```

- [ ] **Step 3: Add CallTypeStats to StatusResponse**

```go
type StatusResponse struct {
    DirectoryStatuses []DirectoryStatus `json:"directoryStatuses"`
    ProcessStatuses   []ProcessStatus   `json:"processStatuses"`
    PortStatuses      []PortStatus      `json:"portStatuses"`
    StreamStats       []StreamStat      `json:"streamStats"`
    CallTypeStats     []CallTypeStat    `json:"callTypeStats"` // 新增：话单类型统计
    Metrics           Metrics           `json:"metrics"`
}
```

- [ ] **Step 4: Add CallTypeStats to cache anonymous struct**

```go
cache = struct {
    mu              sync.RWMutex
    Metrics         Metrics
    ProcessStatuses []ProcessStatus
    StreamStats     []StreamStat
    CallTypeStats   []CallTypeStat // 新增缓存
    LastUpdated     time.Time
    lastCPUEMA          float64
    diskPartitions      []disk.PartitionStat
    lastDiskRefresh     time.Time
    lastTransferRefresh time.Time
    processScanAt       time.Time
}{}
```

- [ ] **Step 5: Commit**

```bash
git add struct_v1.6.go
git commit -m "feat: add CallTypeStat struct and wire into Config/Response/Cache"
```

---

### Task 2: Add collectCallTypeStats() to sup_func_v1.6.go and integrate into collection flow

**Files:**
- Modify: `sup_func_v1.6.go`

**Interfaces:**
- Consumes: `CallTypeStat`, `FileTransferConfig.RecentMinutes`, `cache.CallTypeStats`, `transferStatInterval`
- Produces: `collectCallTypeStats(cfg FileTransferConfig) []CallTypeStat`

- [ ] **Step 1: Add filepath import to sup_func_v1.6.go imports (already present, verify `path/filepath` is imported)**

Already imported at line 9: `"path/filepath"`.

- [ ] **Step 2: Add collectCallTypeStats function at end of file (before IP filter section)**

```go
// collectCallTypeStats 解析统计文件，返回最近 recentMinutes 窗口内按数据流+话单类型+5分钟时间点聚合的统计
func collectCallTypeStats(cfg FileTransferConfig) []CallTypeStat {
    if cfg.RecentMinutes <= 0 {
        return nil
    }

    now := time.Now()
    windowStart := now.Add(-time.Duration(cfg.RecentMinutes) * time.Minute)

    // 确定需要读取的日期文件列表
    datesToRead := []struct {
        date     string
        withSuffix bool
    }{}
    today := now.Format("20060102")
    yesterday := now.Add(-24 * time.Hour).Format("20060102")
    windowStartDate := windowStart.Format("20060102")

    if windowStartDate == today {
        // 窗口全在今天内
        datesToRead = append(datesToRead, struct {
            date       string
            withSuffix bool
        }{today, false})
    } else if windowStartDate == yesterday {
        // 窗口跨到今天和昨天
        datesToRead = append(datesToRead, struct {
            date       string
            withSuffix bool
        }{yesterday, true}, struct {
            date       string
            withSuffix bool
        }{today, false})
    } else {
        // 窗口跨越更多天，读今天+昨天（覆盖绝大多数场景）
        datesToRead = append(datesToRead, struct {
            date       string
            withSuffix bool
        }{yesterday, true}, struct {
            date       string
            withSuffix bool
        }{today, false})
    }

    // 聚合结构: key = "streamName|callType|timePoint"
    agg := make(map[string]*CallTypeStat)

    for _, dr := range datesToRead {
        var fileName string
        if dr.withSuffix {
            fileName = fmt.Sprintf("SFTPOutput.fileLog.stat.%s", dr.date)
        } else {
            fileName = "SFTPOutput.fileLog.stat"
        }
        fullPath := filepath.Join(cfg.LogPath, fileName)

        file, err := os.Open(fullPath)
        if err != nil {
            continue
        }

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            line := scanner.Text()
            parts := strings.Split(line, "|")
            if len(parts) < 14 {
                continue
            }

            streamName := strings.TrimSpace(parts[1])
            filePath := strings.TrimSpace(parts[3])
            fileSizeStr := strings.TrimSpace(parts[4])
            statusStr := strings.TrimSpace(parts[len(parts)-1])

            // 只统计成功的记录
            if statusStr != "0" {
                continue
            }

            // 检查数据流是否在配置中
            streamConfigured := false
            for _, s := range cfg.Streams {
                if s == streamName {
                    streamConfigured = true
                    break
                }
            }
            if !streamConfigured {
                continue
            }

            // 从文件路径中提取文件名并解析话单类型和5分钟时间点
            fileName := filepath.Base(filePath)
            // 例: 100_20260703000011_083.csv 或 100_20260702235500_06_083_006.txt
            underscoreParts := strings.Split(fileName, "_")
            if len(underscoreParts) < 2 {
                continue
            }

            callType := underscoreParts[0]
            timeStr := underscoreParts[1]
            if len(timeStr) < 12 {
                continue
            }
            // 取前12位作为 YYYYMMDDHHMM
            timePoint := timeStr[:12]

            // 解析为时间，检查是否在窗口内
            t, err := time.Parse("200601021504", timePoint)
            if err != nil {
                continue
            }
            if t.Before(windowStart) || t.After(now) {
                continue
            }

            // 解析文件大小
            size, err := strconv.ParseInt(fileSizeStr, 10, 64)
            if err != nil {
                continue
            }

            // 聚合
            key := streamName + "|" + callType + "|" + timePoint
            if existing, ok := agg[key]; ok {
                existing.TotalFiles++
                existing.TotalSize += size
            } else {
                agg[key] = &CallTypeStat{
                    StreamName: streamName,
                    CallType:   callType,
                    TimePoint:  timePoint,
                    TotalFiles: 1,
                    TotalSize:  size,
                }
            }
        }
        file.Close()
    }

    // 转换为切片返回，按 timePoint 排序
    var results []CallTypeStat
    for _, v := range agg {
        results = append(results, *v)
    }
    // 按 timePoint + streamName + callType 排序，保证输出稳定
    sort.Slice(results, func(i, j int) bool {
        if results[i].TimePoint != results[j].TimePoint {
            return results[i].TimePoint < results[j].TimePoint
        }
        if results[i].StreamName != results[j].StreamName {
            return results[i].StreamName < results[j].StreamName
        }
        return results[i].CallType < results[j].CallType
    })

    return results
}
```

- [ ] **Step 3: Add `sort` to imports**

In `sup_func_v1.6.go`, add `"sort"` to the import block.

- [ ] **Step 4: Integrate into doCollectMetrics() — replace the existing File Transfer Stats section (lines 101-122)**

Replace the existing block that calls `collectTransferStats` and updates cache with a version that also collects `CallTypeStats`:

```go
    // 4. File Transfer Stats
    var currentStreamStats []StreamStat
    var currentCallTypeStats []CallTypeStat
    cache.mu.RLock()
    lastTransferRefresh := cache.lastTransferRefresh
    transferConfig := config.FileTransfer
    cache.mu.RUnlock()

    if lastTransferRefresh.IsZero() || now.Sub(lastTransferRefresh) > transferStatInterval {
        newStats := collectTransferStats(transferConfig)
        newCallTypeStats := collectCallTypeStats(transferConfig)

        cache.mu.Lock()
        cache.StreamStats = newStats
        cache.CallTypeStats = newCallTypeStats
        cache.lastTransferRefresh = now
        cache.mu.Unlock()
        currentStreamStats = newStats
        currentCallTypeStats = newCallTypeStats
    } else {
        cache.mu.RLock()
        currentStreamStats = cache.StreamStats
        currentCallTypeStats = cache.CallTypeStats
        cache.mu.RUnlock()
    }
```

- [ ] **Step 5: Update the final cache write in doCollectMetrics() (around line 182-196)**

Replace the line `cache.StreamStats = currentStreamStats` with both stats:

```go
    cache.StreamStats = currentStreamStats
    cache.CallTypeStats = currentCallTypeStats
```

- [ ] **Step 6: Commit**

```bash
git add sup_func_v1.6.go
git commit -m "feat: add collectCallTypeStats with time window filtering and aggregation"
```

---

### Task 3: Include CallTypeStats in JSON handler

**Files:**
- Modify: `json_handle_v1.6.go`

**Interfaces:**
- Consumes: `cache.CallTypeStats`, `CallTypeStat`
- Produces: Updated JSON response with `callTypeStats` field

- [ ] **Step 1: Read CallTypeStats from cache**

In `handler()`, after reading `streamStatsCopy`, add a line to read `CallTypeStats`:

```go
    callTypeStatsCopy := append([]CallTypeStat(nil), cache.CallTypeStats...)
```

Add this right after line 16 (`streamStatsCopy` line).

- [ ] **Step 2: Also read CallTypeStats in the cache-refresh path (inside the select case)**

Inside the `case <-done:` block (after line 36), add:

```go
    callTypeStatsCopy = append([]CallTypeStat(nil), cache.CallTypeStats...)
```

- [ ] **Step 3: Add CallTypeStats to response construction**

Modify the `StatusResponse` literal (around line 101-107):

```go
    response := StatusResponse{
        DirectoryStatuses: directoryStatuses,
        ProcessStatuses:   processesCopy,
        PortStatuses:      portStatuses,
        StreamStats:       streamStatsCopy,
        CallTypeStats:     callTypeStatsCopy,
        Metrics:           metricsCopy,
    }
```

- [ ] **Step 4: Commit**

```bash
git add json_handle_v1.6.go
git commit -m "feat: output callTypeStats in JSON response"
```

---

### Task 4: Add Prometheus metrics for CallTypeStats

**Files:**
- Modify: `prometheus_v1.6.go`

**Interfaces:**
- Consumes: `CallTypeStat`, `cache.CallTypeStats`
- Produces: `server_calltype_files_total`, `server_calltype_size_bytes_total` Prometheus metrics

- [ ] **Step 1: Read CallTypeStats from cache in metricsHandler()**

After reading `streamStatsCopy` from cache (line 18), add:

```go
    callTypeStatsCopy := append([]CallTypeStat(nil), cache.CallTypeStats...)
```

- [ ] **Step 2: Also read CallTypeStats in the cache-refresh path**

Inside the `case <-done:` block (after line 35), add:

```go
    callTypeStatsCopy = append([]CallTypeStat(nil), cache.CallTypeStats...)
```

- [ ] **Step 3: Add callTypeStatsCopy parameter to writePrometheusMetrics call (line 110)**

```go
    writePrometheusMetrics(&sb, instance, metricsCopy, directoryStatuses, processesCopy, portStatuses, streamStatsCopy, callTypeStatsCopy)
```

- [ ] **Step 4: Update writePrometheusMetrics function signature**

```go
func writePrometheusMetrics(sb *strings.Builder, instance string, m Metrics,
    dirs []DirectoryStatus, procs []ProcessStatus, ports []PortStatus, streams []StreamStat, callTypes []CallTypeStat) {
```

- [ ] **Step 5: Add CallTypeStats metrics output at end of writePrometheusMetrics (before closing brace)**

```go
    // --- 话单类型统计 ---
    sb.WriteString("# HELP server_calltype_files_total Call type file count in recent time window.\n")
    sb.WriteString("# TYPE server_calltype_files_total gauge\n")
    for _, ct := range callTypes {
        fmt.Fprintf(sb, "server_calltype_files_total{instance=%q,type=%q,streamName=%q,callType=%q,timePoint=%q} %d\n",
            instance, "stream", ct.StreamName, ct.CallType, ct.TimePoint, ct.TotalFiles)
    }

    sb.WriteString("# HELP server_calltype_size_bytes_total Call type total size in bytes in recent time window.\n")
    sb.WriteString("# TYPE server_calltype_size_bytes_total gauge\n")
    for _, ct := range callTypes {
        fmt.Fprintf(sb, "server_calltype_size_bytes_total{instance=%q,type=%q,streamName=%q,callType=%q,timePoint=%q} %d\n",
            instance, "stream", ct.StreamName, ct.CallType, ct.TimePoint, ct.TotalSize)
    }
```

- [ ] **Step 6: Commit**

```bash
git add prometheus_v1.6.go
git commit -m "feat: output callTypeStats in Prometheus metrics"
```

---

### Task 5: Add recentMinutes to config.json

**Files:**
- Modify: `config.json`

- [ ] **Step 1: Add recentMinutes to fileTransfer config**

```json
    "fileTransfer": {
        "logPath": "/home/haohan/importer/logs/statistic/",
        "streams": ["XDR_SJJS", "XDR_JK"],
        "recentMinutes": 60
    }
```

- [ ] **Step 2: Commit**

```bash
git add config.json
git commit -m "feat: add recentMinutes to fileTransfer config"
```

---

### Task 6: Build and verify

**Files:**
- All modified files

- [ ] **Step 1: Build the project**

```bash
cd D:\go\src\.vscode\hoho\metrics-exporter && go build -o metrics-exporter.exe . 2>&1
```
Expected: No errors.

- [ ] **Step 2: Cross-compile for Linux**

```bash
GOOS=linux GOARCH=amd64 go build -o /dev/null . 2>&1
```
Expected: No errors.

- [ ] **Step 3: Run go vet**

```bash
go vet ./... 2>&1
```
Expected: No errors.

- [ ] **Step 4: Commit (if any build fixes needed)**

```bash
git add -A
git commit -m "chore: fix build issues for calltype stats feature"
```
