package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// metricsHandler: 返回 Prometheus 格式的 metrics 数据
func metricsHandler(w http.ResponseWriter, r *http.Request, cfg Config) {
	// 读取缓存（RLock）
	cache.mu.RLock()
	metricsCopy := cache.Metrics
	processesCopy := append([]ProcessStatus(nil), cache.ProcessStatuses...)
	streamStatsCopy := append([]StreamStat(nil), cache.StreamStats...)
	cacheLastUpdated := cache.LastUpdated
	cache.mu.RUnlock()

	// 如果缓存太旧，尽量触发一次同步采集
	if time.Since(cacheLastUpdated) > cacheTTL {
		done := make(chan struct{}, 1)
		go func() {
			doCollectMetrics()
			done <- struct{}{}
		}()

		select {
		case <-done:
			cache.mu.RLock()
			metricsCopy = cache.Metrics
			processesCopy = append([]ProcessStatus(nil), cache.ProcessStatuses...)
			streamStatsCopy = append([]StreamStat(nil), cache.StreamStats...)
			cache.mu.RUnlock()
		case <-time.After(2 * time.Second):
			log.Printf("Warning: metrics cache stale, returning old values")
		}
	}

	// Directory checks
	date := getCurrentDate()
	timeStr := getCurrentTimeToNearest5()
	timeStrNext := getTimeToNearest5MinNext()
	date1, timeMinus60 := getTimeToNearest5Minus60()

	var directoryStatuses []DirectoryStatus

	configMutex.RLock()
	baseDirs := append([]BaseDirConfig(nil), cfg.BaseDirs...)
	configMutex.RUnlock()
	now := time.Now()

	for _, dirCfg := range baseDirs {
		if !shouldMonitorDir(dirCfg, now) {
			continue
		}
		baseDir := dirCfg.Path

		folderExists, folderPath := checkFolderExists(baseDir, date)
		fileExists := false

		if folderExists {
			fileExistsCurrent, _ := checkFileExistsWithTime(folderPath, date+timeStr)
			fileExistsNext, _ := checkFileExistsWithTime(folderPath, date+timeStrNext)
			fileExists = fileExistsCurrent || fileExistsNext
		} else {
			fileExists, _ = checkFileExistsWithTime(baseDir, date1+timeMinus60)
		}

		directoryStatuses = append(directoryStatuses, DirectoryStatus{
			DirectoryExist: folderExists,
			XdrFileExist:   fileExists,
			BaseDir:        baseDir,
		})
	}

	// Port statuses
	var portStatuses []PortStatus
	configMutex.RLock()
	targets := append([]Target(nil), cfg.Targets...)
	configMutex.RUnlock()

	for _, target := range targets {
		for _, port := range target.Ports {
			status := checkPort(target.Host, port)
			portStatuses = append(portStatuses, PortStatus{
				Host:   target.Host,
				Port:   port,
				Status: status,
			})
		}
	}

	// 获取 instance 标签值
	configMutex.RLock()
	instance := cfg.Instance
	configMutex.RUnlock()
	if instance == "" {
		if hostname, err := os.Hostname(); err == nil {
			instance = hostname
		} else {
			instance = "unknown"
		}
	}

	// 构建 Prometheus 格式输出
	var sb strings.Builder
	writePrometheusMetrics(&sb, instance, metricsCopy, directoryStatuses, processesCopy, portStatuses, streamStatsCopy)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(sb.String()))
}

// writePrometheusMetrics 构建 Prometheus text 格式的指标数据
func writePrometheusMetrics(sb *strings.Builder, instance string, m Metrics,
	dirs []DirectoryStatus, procs []ProcessStatus, ports []PortStatus, streams []StreamStat) {

	// --- 系统指标 ---
	sb.WriteString("# HELP server_cpu_usage_percent CPU usage percentage (EMA smoothed).\n")
	sb.WriteString("# TYPE server_cpu_usage_percent gauge\n")
	fmt.Fprintf(sb, "server_cpu_usage_percent{instance=%q,type=%q} %f\n", instance, "cpu", m.CPUUsage)

	sb.WriteString("# HELP server_memory_usage_percent Memory usage percentage.\n")
	sb.WriteString("# TYPE server_memory_usage_percent gauge\n")
	fmt.Fprintf(sb, "server_memory_usage_percent{instance=%q,type=%q} %f\n", instance, "memory", m.MemoryUsage)

	for mountpoint, usage := range m.DiskUsage {
		sb.WriteString("# HELP server_disk_usage_percent Disk partition usage percentage.\n")
		sb.WriteString("# TYPE server_disk_usage_percent gauge\n")
		fmt.Fprintf(sb, "server_disk_usage_percent{instance=%q,type=%q,mountpoint=%q} %f\n", instance, "disk", mountpoint, usage)
	}

	// --- 目录状态（始终输出，status 标签区分 exist/noexist） ---
	sb.WriteString("# HELP server_directory_exists Directory existence status.\n")
	sb.WriteString("# TYPE server_directory_exists gauge\n")
	for _, ds := range dirs {
		status := "noexist"
		if ds.DirectoryExist {
			status = "exist"
		}
		fmt.Fprintf(sb, "server_directory_exists{instance=%q,type=%q,baseDir=%q,status=%q} 1\n", instance, "directory", ds.BaseDir, status)
	}

	// --- 文件状态（始终输出，status 标签区分 exist/noexist） ---
	sb.WriteString("# HELP server_xdrfile_exists XDR file existence status.\n")
	sb.WriteString("# TYPE server_xdrfile_exists gauge\n")
	for _, ds := range dirs {
		status := "noexist"
		if ds.XdrFileExist {
			status = "exist"
		}
		fmt.Fprintf(sb, "server_xdrfile_exists{instance=%q,type=%q,baseDir=%q,status=%q} 1\n", instance, "directory", ds.BaseDir, status)
	}

	// --- 进程状态（始终输出，status 标签区分 up/down） ---
	sb.WriteString("# HELP server_process_running Process running status.\n")
	sb.WriteString("# TYPE server_process_running gauge\n")
	for _, ps := range procs {
		status := "down"
		if ps.IsRunning {
			status = "up"
		}
		fmt.Fprintf(sb, "server_process_running{instance=%q,type=%q,processName=%q,status=%q} 1\n", instance, "process", ps.ProcessName, status)
	}

	// --- 端口状态（始终输出，status 标签区分 up/down） ---
	sb.WriteString("# HELP server_port_reachable Port reachability status.\n")
	sb.WriteString("# TYPE server_port_reachable gauge\n")
	for _, p := range ports {
		status := "down"
		if p.Status {
			status = "up"
		}
		fmt.Fprintf(sb, "server_port_reachable{instance=%q,type=%q,host=%q,port=%q,status=%q} 1\n", instance, "port", p.Host, fmt.Sprintf("%d", p.Port), status)
	}

	// --- 文件传输统计 ---
	sb.WriteString("# HELP server_stream_total_files Total successful transfer files.\n")
	sb.WriteString("# TYPE server_stream_total_files gauge\n")
	for _, ss := range streams {
		fmt.Fprintf(sb, "server_stream_total_files{instance=%q,type=%q,streamName=%q,statDate=%q} %d\n", instance, "stream", ss.StreamName, ss.StatDate, ss.TotalFiles)
	}

	sb.WriteString("# HELP server_stream_total_size_bytes Total successful transfer size in bytes.\n")
	sb.WriteString("# TYPE server_stream_total_size_bytes gauge\n")
	for _, ss := range streams {
		fmt.Fprintf(sb, "server_stream_total_size_bytes{instance=%q,type=%q,streamName=%q,statDate=%q} %d\n", instance, "stream", ss.StreamName, ss.StatDate, ss.TotalSize)
	}
}
