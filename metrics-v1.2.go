package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/process"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// 告警指标的结构体
type Metrics struct {
	CPUUsage    float64            `json:"cpu_usage"`
	MemoryUsage float64            `json:"memory_usage"`
	DiskUsage   map[string]float64 `json:"disk_usage"`
}

// 初始化结构体，读取配置文件中的多个目录
type Config struct {
	BaseDirs  []BaseDirConfig `json:"baseDirs"`
	Processes []string        `json:"processes"`
	Targets   []Target        `json:"targets"`
}

// 目录和文件是否存在的结构体
type DirectoryStatus struct {
	DirectoryExist bool   `json:"directoryExist"`
	XdrFileExist   bool   `json:"xdrfileExist"`
	BaseDir        string `json:"baseDir"`
}

// 进程状态的结构体
type ProcessStatus struct {
	ProcessName string `json:"processName"`
	IsRunning   bool   `json:"isRunning"`
}

// 返回给中心数据的结构体
type StatusResponse struct {
	DirectoryStatuses []DirectoryStatus `json:"directoryStatuses"`
	ProcessStatuses   []ProcessStatus   `json:"processStatuses"`
	PortStatuses      []PortStatus      `json:"portStatuses"`
	Metrics           Metrics           `json:"metrics"`
}

type Target struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
}

type PortStatus struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Status bool   `json:"status"`
}

type TimeRange struct {
	Start string `json:"start"` // HH:MM
	End   string `json:"end"`   // HH:MM
}

type BaseDirConfig struct {
	Path       string      `json:"path"`
	TimeRanges []TimeRange `json:"timeRanges"`
}

var (
	config      Config
	configMutex sync.RWMutex
	configPath  string
	cache       = struct {
		mu              sync.RWMutex
		Metrics         Metrics
		ProcessStatuses []ProcessStatus
		LastUpdated     time.Time
		// 内部字段：EMA 和磁盘分区缓存
		lastCPUEMA      float64
		diskPartitions  []disk.PartitionStat
		lastDiskRefresh time.Time
		processScanAt   time.Time
	}{}
)

const (
	collectorInterval    = 3 * time.Second  // 后台采集间隔（CPU/内存/进程）
	diskRefreshInterval  = 5 * time.Minute  // 磁盘分区刷新频率
	cacheTTL             = 30 * time.Second // 原来 TTL，兼容保留（但我们使用后台采集）
	emaAlpha             = 0.6              // EMA 平滑系数（0<alpha<=1），值越小越平滑
	cpuSampleNonBlocking = true             // 使用 cpu.Percent(0, false) 来避免阻塞
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
	// CPU: 使用非阻塞采样 + EMA 平滑
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

	// Memory: 更合理的计算方式（排除 buffers & cached）
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

	// Disk: 如果上次刷新超过阈值，则重新获取 partitions 并计算使用率
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

	// 进程扫描：周期性扫描一次 process list，避免每次 handler 调用 pgrep
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
	cache.LastUpdated = now
	cache.mu.Unlock()
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

// handler: 返回缓存结果（并在 handler 内补充 directory/port 状态检查）
func handler(w http.ResponseWriter, r *http.Request, cfg Config) {
	// 读取缓存（RLock）
	cache.mu.RLock()
	metricsCopy := cache.Metrics
	processesCopy := append([]ProcessStatus(nil), cache.ProcessStatuses...)
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
		Metrics:           metricsCopy,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// 主函数
func main() {
	// 解析命令行参数
	installFlag := flag.Bool("i", false, "Install as a service")
	upgradeFlag := flag.Bool("u", false, "Upgrade the service")
	flag.Parse()

	if *installFlag {
		installService()
		return
	}

	if *upgradeFlag {
		if err := upgradeService(); err != nil {
			log.Fatalf("升级失败: %v", err)
		}
		log.Println("服务升级成功")
		return
	}
	// 加载初始配置
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	go startConfigWatcher()

	// 启动后台采集器
	startBackgroundCollector()

	// 启动 HTTP 服务器并处理检查请求
	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) { // 当访问/check路径时，调用匿名函数，这个匿名函数交给handler处理
		handler(w, r, config)
	})
	fmt.Println("Starting HTTP server on port 9600...")
	err := http.ListenAndServe(":9600", nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
