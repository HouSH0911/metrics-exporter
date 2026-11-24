package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// --- 启动后台周期采集 ---

func startBackgroundCollector() {
	// 立即采集一次，之后周期采集
	doCollectMetrics()

	ticker := time.NewTicker(collectorInterval)
	go func() {
		for range ticker.C {
			doCollectMetrics()
		}
	}()
}

// doCollectMetrics: 在后台采集 CPU/Memory/Disk/Processes，并更新 cache（并发安全）
func doCollectMetrics() {
	// 1.CPU: 使用非阻塞采样 + EMA 平滑
	var cpuVal float64
	if cpuSampleNonBlocking {
		if vals, err := cpu.Percent(0, false); err == nil && len(vals) > 0 {
			cpuVal = vals[0]
		} else {
			// 退回到 1s 采样以防万一
			if vals2, err2 := cpu.Percent(1*time.Second, false); err2 == nil && len(vals2) > 0 {
				cpuVal = vals2[0]
			}
		}
	} else {
		if vals, err := cpu.Percent(1*time.Second, false); err == nil && len(vals) > 0 {
			cpuVal = vals[0]
		}
	}

	// 2.Memory: 更合理的计算方式（排除 buffers & cached）
	var memVal float64
	if vm, err := mem.VirtualMemory(); err == nil {
		// 注意： linux 上 Buffers 和 Cached 字段存在，实际使用内存应该减去可回收部分
		used := float64(vm.Used) - float64(vm.Buffers) - float64(vm.Cached)
		if used < 0 {
			used = float64(vm.Used)
		}
		if vm.Total > 0 {
			memVal = (used / float64(vm.Total)) * 100.0
		}
	}

	// 3.Disk: 如果上次刷新超过阈值，则重新获取 partitions 并计算使用率
	var diskUsage map[string]float64
	now := time.Now()
	cache.mu.RLock()
	lastDiskRefresh := cache.lastDiskRefresh // 读取上次刷新时间
	cache.mu.RUnlock()

	if lastDiskRefresh.IsZero() || now.Sub(lastDiskRefresh) > diskRefreshInterval {
		if partitions, err := disk.Partitions(true); err == nil {
			// 尝试获取每个挂载点的 usage
			du := make(map[string]float64)
			for _, p := range partitions {
				if usage, err := disk.Usage(p.Mountpoint); err == nil {
					du[p.Mountpoint] = usage.UsedPercent
				}
			}
			cache.mu.Lock()
			cache.diskPartitions = partitions
			cache.lastDiskRefresh = now
			cache.Metrics.DiskUsage = du
			cache.mu.Unlock()
			diskUsage = du
		} else {
			// 如果获取 partitions 失败，回退读取缓存（如果有）
			cache.mu.RLock()
			diskUsage = cache.Metrics.DiskUsage
			cache.mu.RUnlock()
		}
	} else {
		// 使用缓存结果
		cache.mu.RLock()
		diskUsage = cache.Metrics.DiskUsage
		cache.mu.RUnlock()
	}

	// 4. File Transfer Stats
	var currentStreamStats []StreamStat
	var currentCallTypeStats []CallTypeStat
	cache.mu.RLock()
	lastTransferRefresh := cache.lastTransferRefresh
	cache.mu.RUnlock()
	configMutex.RLock()
	transferConfig := config.FileTransfer
	configMutex.RUnlock()

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

	// 5进程扫描：周期性扫描一次 process list，避免每次 handler 调用 pgrep
	processStatuses := []ProcessStatus{}
	configMutex.RLock()
	procsToCheck := append([]string{}, config.Processes...)
	configMutex.RUnlock()

	// 扫描系统进程（使用 gopsutil）
	// 为了避免频繁遍历 /proc，这里限制扫描频率（与 collectorInterval 相同）
	if now.Sub(cache.processScanAt) > collectorInterval {
		allProcs, _ := process.Processes()
		// 建立进程名索引（小优化）
		nameMap := make(map[string]struct{})
		for _, p := range allProcs {
			if name, err := p.Name(); err == nil {
				nameMap[name] = struct{}{}
			}
		}

		// 对每个目标进程做存在性检测（支持子串匹配）
		for _, pname := range procsToCheck {
			found := false
			// 先尝试精确匹配nameMap，提高效率
			for nm := range nameMap {
				if strings.Contains(nm, pname) {
					found = true
					break
				}
			}
			// 若未找到，再做更慢的逐进程检查（少量情况下才会触发）
			if !found {
				for _, p := range allProcs {
					if cmdline, err := p.Cmdline(); err == nil {
						if strings.Contains(cmdline, pname) {
							found = true
							break
						}
					}
				}
			}
			processStatuses = append(processStatuses, ProcessStatus{
				ProcessName: pname,
				IsRunning:   found,
			})
		}

		// 更新扫描时间
		cache.mu.Lock()
		cache.processScanAt = now
		cache.ProcessStatuses = processStatuses
		cache.mu.Unlock()
	} else {
		// 使用缓存的结果（避免重复扫描）
		cache.mu.RLock()
		processStatuses = cache.ProcessStatuses
		cache.mu.RUnlock()
	}

	// 计算 EMA 并更新 cache.Metrics.CPUUsage
	cache.mu.Lock()
	if cache.lastCPUEMA == 0 {
		cache.lastCPUEMA = cpuVal
	} else {
		cache.lastCPUEMA = emaAlpha*cpuVal + (1-emaAlpha)*cache.lastCPUEMA
	}
	cache.Metrics.CPUUsage = cache.lastCPUEMA
	cache.Metrics.MemoryUsage = memVal
	if diskUsage != nil {
		cache.Metrics.DiskUsage = diskUsage
	}
	cache.ProcessStatuses = processStatuses
	cache.StreamStats = currentStreamStats
	cache.CallTypeStats = currentCallTypeStats
	cache.LastUpdated = now
	cache.mu.Unlock()
}

// 新增：收集文件传输统计信息
func collectTransferStats(cfg FileTransferConfig) []StreamStat {
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour).Format("20060102")
	today := now.Format("20060102")

	// 收集前一天和当天的数据
	yesterdayStats := parseStatFile(cfg, yesterday, true) // 前一天的文件带日期
	todayStats := parseStatFile(cfg, today, false)        // 当天的文件不带日期

	// 合并结果
	return append(yesterdayStats, todayStats...)
}

// 解析指定日期的统计文件
// withDateSuffix: true表示文件名带日期后缀，false表示不带
func parseStatFile(cfg FileTransferConfig, date string, withDateSuffix bool) []StreamStat {
	var fileName string
	if withDateSuffix {
		fileName = fmt.Sprintf("SFTPOutput.fileLog.stat.%s", date)
	} else {
		fileName = "SFTPOutput.fileLog.stat"
	}
	fullPath := filepath.Join(cfg.LogPath, fileName)

	// 初始化结果Map
	statsMap := make(map[string]*StreamStat)
	for _, stream := range cfg.Streams {
		statsMap[stream] = &StreamStat{
			StreamName: stream,
			StatDate:   date,
			TotalFiles: 0,
			TotalSize:  0,
		}
	}

	file, err := os.Open(fullPath)
	if err != nil {
		// 如果文件不存在（比如刚过0点还没生成，或者路径配置错误），记录日志并返回空值的统计
		// log.Printf("Warning: Could not open transfer stat file %s: %v", fullPath, err)
		// 返回初始化的0值
		var results []StreamStat
		for _, s := range statsMap {
			results = append(results, *s)
		}
		return results
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")

		// 简单的校验：根据描述至少需要有12个字段
		// 索引1: 数据流名称
		// 索引4: 文件大小
		// 索引11(最后一个): 状态 (0成功, 1失败)
		if len(parts) < 12 {
			continue
		}

		streamName := strings.TrimSpace(parts[1])
		fileSizeStr := strings.TrimSpace(parts[4])
		statusStr := strings.TrimSpace(parts[len(parts)-1]) // 获取最后一个字段

		// 检查该数据流是否在配置的监控列表中
		stat, exists := statsMap[streamName]
		if !exists {
			continue
		}

		// 检查状态是否成功 ("0" 表示成功)
		if statusStr != "0" {
			continue
		}

		// 解析大小
		size, err := strconv.ParseInt(fileSizeStr, 10, 64)
		if err != nil {
			continue
		}

		// 累加
		stat.TotalFiles++
		stat.TotalSize += size
	}

	// 转换为切片返回
	var results []StreamStat
	for _, stream := range cfg.Streams {
		if s, ok := statsMap[stream]; ok {
			results = append(results, *s)
		}
	}
	return results
}

// 判断当前时间是否在时间段内
func inTimeRange(r TimeRange, now time.Time) bool {
	layout := "15:04"

	start, err1 := time.Parse(layout, r.Start)
	end, err2 := time.Parse(layout, r.End)
	if err1 != nil || err2 != nil {
		return false
	}

	nowMin := now.Hour()*60 + now.Minute()
	startMin := start.Hour()*60 + start.Minute()
	endMin := end.Hour()*60 + end.Minute()

	// 普通时间段：09:00 - 18:00
	if startMin <= endMin {
		return nowMin >= startMin && nowMin <= endMin
	}

	// 跨天时间段：23:00 - 02:00
	return nowMin >= startMin || nowMin <= endMin
}

// 判断是否需要监控该目录（基于时间段配置）
func shouldMonitorDir(dir BaseDirConfig, now time.Time) bool {
	// 没配时间段 = 默认全天监控（向后兼容）
	if len(dir.TimeRanges) == 0 {
		return true
	}

	for _, r := range dir.TimeRanges {
		if inTimeRange(r, now) {
			return true
		}
	}
	return false
}

// 获取当前日期，格式为 YYYYMMDD
func getCurrentDate() string {
	return time.Now().Format("20060102")
}

// 获取当前时间精确到整5分钟
func getCurrentTimeToNearest5() string {
	now := time.Now()
	minute := now.Minute() - now.Minute()%5 // 取当前分钟的整5分钟
	return fmt.Sprintf("%02d%02d", now.Hour(), minute)
}

// 获取当前时间前5分钟的整5分钟
func getTimeToNearest5MinNext() string {
	now := time.Now().Add(-5 * time.Minute)
	//date := now.Format("20060102")
	minute := now.Minute() - now.Minute()%5
	return fmt.Sprintf("%02d%02d", now.Hour(), minute)
}

// 获取当前时间前几十分钟的整5分钟，避免有的服务器备份延迟
func getTimeToNearest5Minus60() (string, string) {
	now := time.Now().Add(-70 * time.Minute)
	date := now.Format("20060102")
	minute := now.Minute() - now.Minute()%5
	return date, fmt.Sprintf("%02d%02d", now.Hour(), minute)
}

// 获取当前时间后5分钟的整5分钟（下一个五分钟点），返回日期和时间，处理跨天场景
func getTimeToNearest5Plus5() (string, string) {
	now := time.Now().Add(5 * time.Minute)
	date := now.Format("20060102")
	minute := now.Minute() - now.Minute()%5
	return date, fmt.Sprintf("%02d%02d", now.Hour(), minute)
}

// 检查指定主机和端口是否可达
func checkPort(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// 检查指定目录下是否存在指定日期的文件夹
func checkFolderExists(baseDir, date string) (bool, string) {
	folderPath := filepath.Join(baseDir, date)
	_, err := os.Stat(folderPath)
	if os.IsNotExist(err) {
		return false, folderPath
	}
	return true, folderPath
}

// 检查指定文件夹下是否存在文件名包含指定时间的文件
func checkFileExistsWithTime(folderPath, timeStr string) (bool, string) {
	files, err := os.ReadDir(folderPath)
	if err != nil {
		log.Printf("Failed to read directory: %v", err)
		return false, timeStr
	}

	for _, file := range files {
		if strings.Contains(file.Name(), timeStr) {
			return true, timeStr
		}
	}
	return false, timeStr
}

// 使缓存失效
func invalidateCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.LastUpdated = time.Time{} // 设置为零值使缓存失效
}

// collectCallTypeStats 解析统计文件，返回最近 recentMinutes 窗口内按数据流+话单类型+5分钟时间点聚合的统计
func collectCallTypeStats(cfg FileTransferConfig) []CallTypeStat {
	if cfg.RecentMinutes <= 0 {
		return nil
	}

	now := time.Now()
	windowStart := now.Add(-time.Duration(cfg.RecentMinutes) * time.Minute)

	// 确定需要读取的日期文件列表
	datesToRead := []struct {
		date       string
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
	} else {
		// 窗口跨到今天/昨天，或跨越更多天（覆盖绝大多数场景）
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

		// 构建配置数据流查找集合
		streamSet := make(map[string]bool, len(cfg.Streams))
		for _, s := range cfg.Streams {
			streamSet[s] = true
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
			if !streamSet[streamName] {
				continue
			}

			// 从文件路径中提取文件名并解析话单类型和5分钟时间点
			baseName := filepath.Base(filePath)
			// 例: 100_20260703000011_083.csv 或 100_20260702235500_06_083_006.txt
			underscoreParts := strings.Split(baseName, "_")
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

			// 解析为时间（使用北京时间），检查是否在窗口内
			loc, _ := time.LoadLocation("Asia/Shanghai")
			t, err := time.ParseInLocation("200601021504", timePoint, loc)
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

// == 访问控制相关逻辑 ==============================================================================================
// getIPFromAddr 从 "host:port" 字符串中提取 IP
func getIPFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// isAllowed 检查客户端IP是否在允许列表中，支持：单IP、CIDR网段
func isAllowed(allowedHosts []string, clientIP string) bool {
	client := net.ParseIP(clientIP)
	if client == nil {
		return false
	}
	for _, item := range allowedHosts {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			_, cidr, err := net.ParseCIDR(item)
			if err == nil && cidr.Contains(client) {
				return true
			}
		} else if item == clientIP {
			return true
		}
	}
	return false
}

func (l *ipFilterListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		configMutex.RLock()
		allowedHosts := config.AllowedHosts
		configMutex.RUnlock()

		// 未配置访问控制，直接放行
		if len(allowedHosts) == 0 {
			return conn, nil
		}

		clientIP := getIPFromAddr(conn.RemoteAddr().String())
		if isAllowed(allowedHosts, clientIP) {
			return conn, nil
		}

		conn.Close()
	}
}

func (l *ipFilterListener) Close() error {
	return l.inner.Close()
}

func (l *ipFilterListener) Addr() net.Addr {
	return l.inner.Addr()
}
