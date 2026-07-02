package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

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
	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, config)
	})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metricsHandler(w, r, config)
	})

	port := config.Port
	if port == 0 {
		port = 9600 // 默认端口
	}

	addr := fmt.Sprintf(":%d", port)
	rawListener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	filteredListener := &ipFilterListener{inner: rawListener}
	fmt.Printf("Starting HTTP server on port %d...\n", port)
	err = http.Serve(filteredListener, nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
