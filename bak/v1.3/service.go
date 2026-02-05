package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// 安装为系统服务
func installService() {
	fmt.Println("安装 mereics-exporter 服务...")

	// 获取当前工作目录
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("获取当前目录失败: %v", err)
	}

	// 获取可执行文件路径
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("获取可执行文件路径失败: %v", err)
	}

	installLinuxService(cwd, exePath)
}
func installLinuxService(cwd, exePath string) {
	// 检查系统类型（CentOS 6 或 7）
	isCentOS6 := false
	if out, err := exec.Command("cat", "/etc/redhat-release").Output(); err == nil {
		if strings.Contains(string(out), "release 6") {
			isCentOS6 = true
			log.Println("检测到 CentOS 6 系统，使用 SysVinit 脚本")
		} else {
			log.Println("检测到 CentOS 7 或更高版本，使用 systemd")
		}
	} else {
		log.Printf("无法确定系统版本，默认使用 systemd: %v", err)
	}

	if isCentOS6 {
		installCentOS6Service(cwd, exePath)
	} else {
		installSystemdService(cwd, exePath)
	}
}

func installSystemdService(cwd, exePath string) {
	// 确保目录存在
	serviceDir := "/etc/systemd/system"
	if _, err := os.Stat(serviceDir); os.IsNotExist(err) {
		if err := os.MkdirAll(serviceDir, 0755); err != nil {
			log.Fatalf("创建目录 %s 失败: %v", serviceDir, err)
		}
	}

	// 创建systemd服务文件
	serviceContent := fmt.Sprintf(`[Unit]
Description=Server metrics-exporter Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=5
Environment=GIN_MODE=release

[Install]
WantedBy=multi-user.target
`, cwd, exePath)

	// 保存服务文件
	servicePath := filepath.Join(serviceDir, "metrics-exporter.service")
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		log.Fatalf("创建服务文件失败: %v", err)
	}

	// 重新加载systemd配置
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		log.Fatalf("重新加载systemd配置失败: %v", err)
	}

	// 启用服务
	cmd = exec.Command("systemctl", "enable", "metrics-exporter.service")
	if err := cmd.Run(); err != nil {
		log.Fatalf("启用服务失败: %v", err)
	}

	// 启动服务
	cmd = exec.Command("systemctl", "start", "metrics-exporter.service")
	if err := cmd.Run(); err != nil {
		log.Fatalf("启动服务失败: %v", err)
	}

	fmt.Println("systemd 服务安装成功！")
}

func installCentOS6Service(cwd, exePath string) {
	// 确保目录存在
	initDir := "/etc/init.d"
	if _, err := os.Stat(initDir); os.IsNotExist(err) {
		if err := os.MkdirAll(initDir, 0755); err != nil {
			log.Fatalf("创建目录 %s 失败: %v", initDir, err)
		}
	}

	// 创建SysVinit脚本
	initScript := fmt.Sprintf(`#!/bin/bash
# chkconfig: 345 85 15
# description: Whether file and process exist Service

### BEGIN INIT INFO
# Provides: metrics-exporter
# Required-Start: $local_fs $network
# Required-Stop: $local_fs $network
# Default-Start: 3 4 5
# Default-Stop: 0 1 2 6
# Short-Description: Collect server metrics
# Description: metrics-exporter
### END INIT INFO

# 服务名称
NAME="metrics-exporter"
EXEC="%s"
WORKDIR="%s"
PIDFILE="/var/run/$NAME.pid"
LOGFILE="%s/$NAME.log"

start() {
    echo -n $"Starting $NAME: "
    if [ -f $PIDFILE ]; then
        PID=$(cat $PIDFILE)
        if ps -p $PID > /dev/null; then
            echo "already running (pid $PID)"
            return 0
        fi
    fi
    
    cd $WORKDIR
    nohup $EXEC > $LOGFILE 2>&1 &
    PID=$!
    echo $PID > $PIDFILE
    echo "started (pid $PID)"
    return 0
}

stop() {
    echo -n $"Stopping $NAME: "
    if [ -f $PIDFILE ]; then
        PID=$(cat $PIDFILE)
        if ps -p $PID > /dev/null; then
            kill $PID
            echo "stopped (pid $PID)"
        else
            echo "not running"
        fi
        rm -f $PIDFILE
    else
        echo "not running"
    fi
    return 0
}

restart() {
    stop
    sleep 1
    start
}

status() {
    if [ -f $PIDFILE ]; then
        PID=$(cat $PIDFILE)
        if ps -p $PID > /dev/null; then
            echo "$NAME is running (pid $PID)"
            return 0
        else
            echo "$NAME is stopped but pid file exists"
            return 1
        fi
    else
        echo "$NAME is stopped"
        return 3
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|status}"
        exit 2
esac

exit $?
`, exePath, cwd, cwd)

	// 保存脚本
	scriptPath := filepath.Join(initDir, "metrics-exporter")
	if err := os.WriteFile(scriptPath, []byte(initScript), 0755); err != nil {
		log.Fatalf("创建init脚本失败: %v", err)
	}

	// 添加服务到启动项
	cmd := exec.Command("chkconfig", "--add", "metrics-exporter")
	if err := cmd.Run(); err != nil {
		log.Fatalf("添加服务失败: %v", err)
	}

	// 启用服务
	cmd = exec.Command("chkconfig", "metrics-exporter", "on")
	if err := cmd.Run(); err != nil {
		log.Fatalf("启用服务失败: %v", err)
	}

	// 启动服务
	cmd = exec.Command("service", "metrics-exporter", "start")
	if err := cmd.Run(); err != nil {
		log.Fatalf("启动服务失败: %v", err)
	}

	fmt.Println("SysVinit 服务安装成功！")
}

// 升级服务
func upgradeService() error {
	// 检查服务状态
	if isServiceActive() {
		return fmt.Errorf("服务正在运行，请先停止服务后再升级")
	}

	// 删除旧的服务文件
	if err := removeOldServiceFiles(); err != nil {
		return fmt.Errorf("删除旧服务文件失败: %v", err)
	}

	// 重新安装服务
	fmt.Println("重新安装服务...")
	installService()

	// 启动服务
	if err := startService(); err != nil {
		log.Printf("警告: 启动服务失败: %v", err)
	}

	log.Println("服务升级成功!")
	return nil
}

// 删除旧的服务文件
func removeOldServiceFiles() error {
	// 删除 systemd 服务文件
	systemdPath := "/etc/systemd/system/metrics-exporter.service"
	if _, err := os.Stat(systemdPath); err == nil {
		log.Printf("删除 systemd 服务文件: %s", systemdPath)
		if err := os.Remove(systemdPath); err != nil {
			return fmt.Errorf("删除 %s 失败: %v", systemdPath, err)
		}

		// 重新加载 systemd
		cmd := exec.Command("systemctl", "daemon-reload")
		if err := cmd.Run(); err != nil {
			log.Printf("重新加载 systemd 失败: %v", err)
		}
		log.Printf("重新加载 systemd 服务成功!")
	}

	// 删除 SysVinit 脚本
	initdPath := "/etc/init.d/metrics-exporter"
	if _, err := os.Stat(initdPath); err == nil {
		log.Printf("删除 SysVinit 脚本: %s", initdPath)
		if err := os.Remove(initdPath); err != nil {
			return fmt.Errorf("删除 %s 失败: %v", initdPath, err)
		}
	}

	// 删除 PID 文件
	pidPath := "/var/run/metrics-exporter.pid"
	if _, err := os.Stat(pidPath); err == nil {
		log.Printf("删除 PID 文件: %s", pidPath)
		os.Remove(pidPath)
	}

	return nil
}

// 检查服务是否正在运行
func isServiceActive() bool {
	// 检查systemd服务
	if _, err := os.Stat("/etc/systemd/system/metrics-exporter.service"); err == nil {
		cmd := exec.Command("systemctl", "is-active", "metrics-exporter.service")
		output, err := cmd.CombinedOutput()
		return err == nil && strings.TrimSpace(string(output)) == "active"
	}

	// 检查SysVinit服务
	if _, err := os.Stat("/etc/init.d/metrics-exporter"); err == nil {
		cmd := exec.Command("service", "metrics-exporter", "status")
		output, err := cmd.CombinedOutput()
		return err == nil && strings.Contains(string(output), "running")
	}

	// 检查PID文件
	if _, err := os.Stat("/var/run/metrics-exporter.pid"); err == nil {
		return true
	}

	return false
}

// 启动服务
func startService() error {
	// 尝试使用systemd启动
	if _, err := os.Stat("/etc/systemd/system/metrics-exporter.service"); err == nil {
		cmd := exec.Command("systemctl", "start", "metrics-exporter.service")
		return cmd.Run()
	}

	// 尝试使用SysVinit启动
	if _, err := os.Stat("/etc/init.d/metrics-exporter"); err == nil {
		cmd := exec.Command("service", "metrics-exporter", "start")
		return cmd.Run()
	}

	return fmt.Errorf("未找到服务管理文件")
}

// loadConfig reads and parses the configuration file
func loadConfig() error {
	// 获取可执行文件所在目录
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error getting executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	configPath = filepath.Join(exeDir, "config.json") // 设置全局变量

	return reloadConfig()
}

func reloadConfig() error {
	configMutex.Lock() // 写锁
	defer configMutex.Unlock()

	log.Println("Reloading configuration...")

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config.json not found in %s", filepath.Dir(configPath))
	}

	// 读取配置文件
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	// 解析JSON
	var newConfig Config
	if err := json.Unmarshal(configFile, &newConfig); err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	// 更新全局配置
	config = newConfig
	log.Printf("配置已重新加载 - 目录: %v, 进程: %v, 目的服务器：%v", config.BaseDirs, config.Processes, config.Targets)

	invalidateCache()
	return nil
}

// 监控配置文件
func startConfigWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Error creating watcher: %v", err)
	}
	defer watcher.Close()

	configDir := filepath.Dir(configPath)
	// 监控目录而不是单个文件
	if err := watcher.Add(configDir); err != nil {
		log.Fatalf("Error watching config directory: %v", err)
	}
	log.Printf("监控配置目录: %s", configDir)

	// 防抖计时器
	var debounceTimer *time.Timer
	debounceDelay := 500 * time.Millisecond

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// 只处理目标配置文件的事件
			if filepath.Base(event.Name) != "config.json" {
				continue
			}

			log.Printf("配置文件事件: %s", event)

			// 处理所有相关事件
			if event.Op&(fsnotify.Write|fsnotify.Rename|fsnotify.Create|fsnotify.Chmod) != 0 {
				// 取消之前的定时器
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				// 设置新的防抖定时器
				debounceTimer = time.AfterFunc(debounceDelay, func() {
					log.Println("配置文件变更，重新加载...")
					if err := reloadConfig(); err != nil {
						log.Printf("重新加载配置失败: %v", err)
					} else {
						log.Println("配置重新加载成功")
					}
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("监控错误: %v", err)
		}
	}
}
