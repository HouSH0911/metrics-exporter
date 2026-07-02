package main

import (
	"net"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
)

// 告警指标的结构体
type Metrics struct {
	CPUUsage    float64            `json:"cpu_usage"`
	MemoryUsage float64            `json:"memory_usage"`
	DiskUsage   map[string]float64 `json:"disk_usage"`
}

// v1.4新增：文件传输监控配置
type FileTransferConfig struct {
	LogPath string   `json:"logPath"` // 统计日志所在的目录
	Streams []string `json:"streams"` // 需要统计的数据流名称列表
}

// v1.4新增：文件传输统计结果
type StreamStat struct {
	StreamName string `json:"streamName"`
	TotalFiles int64  `json:"totalFiles"` // 成功传输的文件总数
	TotalSize  int64  `json:"totalSize"`  // 成功传输的文件总大小(字节)
	StatDate   string `json:"statDate"`   // 统计的日期(YYYYMMDD)
}

// 初始化结构体，读取配置文件中的多个目录
type Config struct {
	Port         int                `json:"port"`
	Instance     string             `json:"instance"`     // 本机标识，用于Prometheus指标的instance标签，未配置时自动获取hostname
	AllowedHosts []string           `json:"allowedHosts"` // 允许访问/check端点的地址，支持单个IP、CIDR网段
	BaseDirs     []BaseDirConfig    `json:"baseDirs"`
	Processes    []string           `json:"processes"`
	Targets      []Target           `json:"targets"`
	FileTransfer FileTransferConfig `json:"fileTransfer"` // 新增配置段
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
	StreamStats       []StreamStat      `json:"streamStats"` // 新增：传输统计结果
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

// ipFilterListener 在 TCP 层面拒绝非授权 IP 的连接
type ipFilterListener struct {
	inner net.Listener
}

var (
	config      Config
	configMutex sync.RWMutex
	configPath  string
	cache       = struct {
		mu              sync.RWMutex
		Metrics         Metrics
		ProcessStatuses []ProcessStatus
		StreamStats     []StreamStat // 新增缓存
		LastUpdated     time.Time
		// 内部字段：EMA 和磁盘分区缓存
		lastCPUEMA          float64
		diskPartitions      []disk.PartitionStat
		lastDiskRefresh     time.Time
		lastTransferRefresh time.Time // 新增：上次刷新传输统计的时间
		processScanAt       time.Time
	}{}
)

const (
	collectorInterval    = 10 * time.Second // 后台采集间隔（CPU/内存/进程）
	diskRefreshInterval  = 2 * time.Minute  // 磁盘分区刷新频率
	transferStatInterval = 30 * time.Second // 文件传输统计刷新频率
	cacheTTL             = 30 * time.Second // 原来 TTL，兼容保留（但我们使用后台采集）
	emaAlpha             = 0.6              // EMA 平滑系数（0<alpha<=1），值越小越平滑
	cpuSampleNonBlocking = true             // 使用 cpu.Percent(0, false) 来避免阻塞
)
