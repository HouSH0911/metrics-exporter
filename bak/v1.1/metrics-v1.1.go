package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	BaseDirs  []string `json:"baseDirs"`
	Processes []string `json:"processes"`
	Targets   []Target `json:"targets"`
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

// 缓存结构体
type Cache struct {
	Metrics         Metrics
	ProcessStatuses []ProcessStatus
	LastUpdated     time.Time
	mu              sync.RWMutex
}

var (
	config      Config
	configMutex sync.RWMutex
	configPath  string
	cache       = &Cache{}
)

// 缓存有效期（秒）
const cacheTTL = 35 * time.Second

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

// 获取CPU利用率的函数
func getCPUUsage() (float64, error) {
	percentages, err := cpu.Percent(0, false)
	if err != nil || len(percentages) == 0 {
		return 0, err
	}
	return percentages[0], nil
}

// 获取内存利用率的函数
func getMemoryUsage() (float64, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	// 实际使用的内存 = Used + Buffers + Cached
	actualUsed := float64(v.Used) + float64(v.Buffers) + float64(v.Cached)
	total := float64(v.Total)
	return (actualUsed / total) * 100, nil // 返回百分比
}

// 获取所有磁盘利用率
func getDiskUsage() (map[string]float64, error) {
	diskUsage := make(map[string]float64)
	// 获取所有磁盘分区
	partitions, err := disk.Partitions(true)
	if err != nil {
		return nil, err
	}
	// 遍历每个分区，获取其使用率
	for _, partition := range partitions {
		usage, err := disk.Usage(partition.Mountpoint)
		if err == nil {
			diskUsage[partition.Mountpoint] = usage.UsedPercent
		}
	}
	return diskUsage, nil
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

// 检查指定进程是否在运行
func checkProcessRunning(processName string) bool {
	cmd := exec.Command("pgrep", "-f", processName)
	err := cmd.Run()
	return err == nil // 如果运行成功，则进程存在
}

// 获取缓存的数据，如果缓存过期或不存在则重新获取
func getCachedData(config Config) (Metrics, []ProcessStatus, error) {
	cache.mu.RLock()
	// 检查缓存是否有效
	if time.Since(cache.LastUpdated) < cacheTTL && cache.Metrics.CPUUsage > 0 {
		metrics := cache.Metrics
		processStatuses := cache.ProcessStatuses
		//diskUsage := cache.DiskUsage
		cache.mu.RUnlock()
		return metrics, processStatuses, nil
	}
	cache.mu.RUnlock()

	// 缓存无效，重新获取数据
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// 双重检查，防止多个goroutine同时进入临界区
	if time.Since(cache.LastUpdated) < cacheTTL && cache.Metrics.CPUUsage > 0 {
		return cache.Metrics, cache.ProcessStatuses, nil
	}

	// 获取CPU使用率
	cpuUsage, err := getCPUUsage()
	if err != nil {
		return Metrics{}, nil, err
	}

	// 获取内存使用率
	memoryUsage, err := getMemoryUsage()
	if err != nil {
		return Metrics{}, nil, err
	}

	// 获取磁盘使用率
	diskUsage, err := getDiskUsage()
	if err != nil {
		return Metrics{}, nil, err
	}

	// 检查所有配置的进程是否运行
	var processStatuses []ProcessStatus
	for _, processName := range config.Processes {
		isRunning := checkProcessRunning(processName)
		processStatuses = append(processStatuses, ProcessStatus{
			ProcessName: processName,
			IsRunning:   isRunning,
		})
	}

	// 更新缓存
	cache.Metrics = Metrics{
		CPUUsage:    cpuUsage,
		MemoryUsage: memoryUsage,
		DiskUsage:   diskUsage,
	}
	cache.ProcessStatuses = processStatuses
	cache.LastUpdated = time.Now()

	return cache.Metrics, cache.ProcessStatuses, nil
}

// 使缓存失效
func invalidateCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.LastUpdated = time.Time{} // 设置为零值使缓存失效
}

// HTTP 处理器，用于检查是否存在符合条件的文件夹和文件
func handler(w http.ResponseWriter, r *http.Request, config Config) {
	date := getCurrentDate()
	// 当前整五分钟的时间
	timeStr := getCurrentTimeToNearest5()
	// 5分钟前的整五分钟时间
	timeStrNext := getTimeToNearest5MinNext()
	// back 60 minutes
	date1, timeMinus60 := getTimeToNearest5Minus60()
	// print timestring of  defined
	//log.Printf("currenttime:%s", date+timeStr)
	//log.Printf("currenttime-5:%s", date+timeStrNext)
	log.Printf("currenttime-70:%s", date1+timeMinus60)
	var directoryStatuses []DirectoryStatus

	// 从缓存获取数据
	metrics, processStatuses, err := getCachedData(config)
	if err != nil {
		http.Error(w, "Failed to get cached data", http.StatusInternalServerError)
		return
	}
	//var processStatuses []ProcessStatus

	// 遍历所有基础目录并检查文件夹和文件的状态
	for _, baseDir := range config.BaseDirs {
		folderExists, folderPath := checkFolderExists(baseDir, date)
		fileExists := false
		fileExistsCurrent := false
		fileExistsNext := false

		if folderExists {
			fileExistsCurrent, _ = checkFileExistsWithTime(folderPath, date+timeStr)
			fileExistsNext, _ = checkFileExistsWithTime(folderPath, date+timeStrNext)
			fileExists = fileExistsCurrent || fileExistsNext
		} else {
			// 如果日期文件夹不存在，直接在根目录下查找包含时间的文件
			fileExists, _ = checkFileExistsWithTime(baseDir, date1+timeMinus60)
		}

		// 记录每个基础目录的监控状态，将状态append插入进去
		directoryStatuses = append(directoryStatuses, DirectoryStatus{
			DirectoryExist: folderExists,
			XdrFileExist:   fileExists,
			BaseDir:        baseDir,
		})
	}

	// 新增端口状态检测
	var portStatuses []PortStatus
	for _, target := range config.Targets {
		for _, port := range target.Ports {
			status := checkPort(target.Host, port)
			portStatuses = append(portStatuses, PortStatus{
				Host:   target.Host,
				Port:   port,
				Status: status,
			})
		}
	}

	// 设置响应内容
	// 将两个在服务器上获取的目录状态和进程状态一起整合到响应结构体StatusResponse中，时返回给中心curl时的数据格式
	response := StatusResponse{
		DirectoryStatuses: directoryStatuses,
		ProcessStatuses:   processStatuses,
		PortStatuses:      portStatuses, // 新增端口状态
		Metrics:           metrics,
	}

	// 设置响应头为 JSON
	w.Header().Set("Content-Type", "application/json")
	// 将response编码为json格式并写入到响应体当中，也就是定义的w中
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode JSON response", http.StatusInternalServerError)
	}
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

	// 启动 HTTP 服务器并处理检查请求
	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) { // 当访问/check路径时，调用匿名函数，这个匿名函数交给handler处理
		handler(w, r, config)
	})
	fmt.Println("Starting HTTP server on port 8761...")
	err := http.ListenAndServe(":8761", nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
