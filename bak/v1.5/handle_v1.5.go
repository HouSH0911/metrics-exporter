package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// handler: 返回缓存结果（并在 handler 内补充 directory/port 状态检查）
func handler(w http.ResponseWriter, r *http.Request, cfg Config) {
	// 读取缓存（RLock）
	cache.mu.RLock()
	metricsCopy := cache.Metrics
	processesCopy := append([]ProcessStatus(nil), cache.ProcessStatuses...)
	streamStatsCopy := append([]StreamStat(nil), cache.StreamStats...) // 复制一份新的统计数据
	cacheLastUpdated := cache.LastUpdated
	cache.mu.RUnlock()

	// 如果缓存太旧（例如极端情况），尽量触发一次同步采集（非阻塞）
	if time.Since(cacheLastUpdated) > cacheTTL {
		// 触发一次后台采集（同步调用以减少返回空数据的概率）
		// 但不要阻塞太久，最多等待 collectorInterval
		done := make(chan struct{}, 1)
		go func() {
			doCollectMetrics()
			done <- struct{}{}
		}()

		select {
		case <-done:
			// 刚更新过，重新读取缓存
			cache.mu.RLock()
			metricsCopy = cache.Metrics
			processesCopy = append([]ProcessStatus(nil), cache.ProcessStatuses...)
			streamStatsCopy = append([]StreamStat(nil), cache.StreamStats...)
			cache.mu.RUnlock()
		case <-time.After(2 * time.Second):
			// 超时，继续使用旧缓存
			log.Printf("Warning: metrics cache stale, returning old values")
		}
	}

	// Directory checks: 仍在 handler 内执行（因为牵涉文件系统）
	date := getCurrentDate()
	timeStr := getCurrentTimeToNearest5()
	timeStrNext := getTimeToNearest5MinNext()
	date1, timeMinus60 := getTimeToNearest5Minus60()

	var directoryStatuses []DirectoryStatus

	configMutex.RLock()
	baseDirs := append([]BaseDirConfig(nil), cfg.BaseDirs...)
	configMutex.RUnlock()
	now := time.Now()

	// 遍历所有配置的 baseDir
	for _, dirCfg := range baseDirs {
		// 不在监控时间段，直接跳过
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

	// Port statuses (按配置 target 检测)
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

	// 组装响应
	response := StatusResponse{
		DirectoryStatuses: directoryStatuses,
		ProcessStatuses:   processesCopy,
		PortStatuses:      portStatuses,
		StreamStats:       streamStatsCopy, // 返回新增的统计
		Metrics:           metricsCopy,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
