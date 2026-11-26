package bridge

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ignoredSystemProcesses = map[string]struct{}{
	"system idle process": {},
	"system":              {},
	"registry":            {},
	"memory compression":  {},
	"smss.exe":            {},
	"csrss.exe":           {},
	"wininit.exe":         {},
	"winlogon.exe":        {},
	"services.exe":        {},
	"lsass.exe":           {},
	"svchost.exe":         {},
	"fontdrvhost.exe":     {},
	"dwm.exe":             {},
	"conhost.exe":         {},
	"sihost.exe":          {},
	"taskhostw.exe":       {},
	"tasklist.exe":        {},
	"spoolsv.exe":         {},
	"ctfmon.exe":          {},
	"audiodg.exe":         {},
	"wudfhost.exe":        {},
	"searchindexer.exe":   {},
	"runtimebroker.exe":   {},
	"dllhost.exe":         {},
	"proxybridge_cli.exe": {},
	"proxybridge.exe":     {},
}

const (
	tcpStateClosed = 1
	tcpStateListen = 2

	maxSampleTargetsPerProcess = 3
)

// ProcessInfo 描述单个去重后运行进程的展示信息（含应用描述、可见主窗口标题及活跃外联 TCP 统计）。
type ProcessInfo struct {
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	WindowTitle       string   `json:"windowTitle,omitempty"`
	HasWindow         bool     `json:"hasWindow,omitempty"`
	ActiveConnections int      `json:"active_connections"`
	SampleTargets     []string `json:"sample_targets"`
}

// TCPConnectionEntry 描述操作系统 TCP 连接表中的单条记录（用于按进程名聚合活跃外联统计）。
type TCPConnectionEntry struct {
	PID        uint32
	RemoteIP   net.IP
	RemotePort uint16
	State      uint32
}

// IsOutboundTCPTarget 判断单条 TCP 连接是否为有效的非回环、非未绑定外联目标。
func IsOutboundTCPTarget(ip net.IP, port uint16, state uint32) bool {
	if state == tcpStateClosed || state == tcpStateListen {
		return false
	}
	if port == 0 || len(ip) == 0 {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	return true
}

// AggregateActiveConnections 将操作系统活跃 TCP 连接记录按 PID → 进程名聚合至 ProcessInfo 列表，
// 过滤纯回环与未绑定地址，统计外联连接数并最多保留 3 个去重远端 IP:Port 示例，最后按规范排序。
func AggregateActiveConnections(items []ProcessInfo, pidToName map[uint32]string, conns []TCPConnectionEntry) {
	byLower := make(map[string]*ProcessInfo, len(items))
	for i := range items {
		items[i].ActiveConnections = 0
		items[i].SampleTargets = []string{}
		byLower[strings.ToLower(strings.TrimSpace(items[i].Name))] = &items[i]
	}

	seenTargets := make(map[string]map[string]struct{}, len(items))
	for _, conn := range conns {
		if !IsOutboundTCPTarget(conn.RemoteIP, conn.RemotePort, conn.State) {
			continue
		}
		procName, ok := pidToName[conn.PID]
		if !ok || procName == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(procName))
		item, exists := byLower[lower]
		if !exists {
			continue
		}

		item.ActiveConnections++
		if len(item.SampleTargets) >= maxSampleTargetsPerProcess {
			continue
		}

		ip := conn.RemoteIP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		target := net.JoinHostPort(ip.String(), strconv.Itoa(int(conn.RemotePort)))
		set := seenTargets[lower]
		if set == nil {
			set = make(map[string]struct{}, maxSampleTargetsPerProcess)
			seenTargets[lower] = set
		}
		if _, dup := set[target]; !dup {
			set[target] = struct{}{}
			item.SampleTargets = append(item.SampleTargets, target)
		}
	}

	SortProcessDetails(items)
}

func shouldIncludeProcessName(name, selfExe string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(lower, ".exe") {
		return false
	}
	if _, skip := ignoredSystemProcesses[lower]; skip {
		return false
	}
	if selfExe != "" && lower == selfExe {
		return false
	}
	return true
}

// SortProcessDetails 按活跃外联连接数降序排列；当均无外联连接时优先展示有可见窗口的桌面应用，再按进程名大小写不敏感升序排列。
func SortProcessDetails(items []ProcessInfo) {
	slices.SortFunc(items, func(a, b ProcessInfo) int {
		if a.ActiveConnections != b.ActiveConnections {
			if a.ActiveConnections > b.ActiveConnections {
				return -1
			}
			return 1
		}
		if a.ActiveConnections == 0 && a.HasWindow != b.HasWindow {
			if a.HasWindow {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
}

// ListRunningProcessDetails 获取当前运行中的去重 .exe 进程详情列表（含 PE 应用名与可见窗口标题）。
func ListRunningProcessDetails(ctx context.Context) ([]ProcessInfo, error) {
	return listRunningProcessDetailsPlatform(ctx)
}

// ListRunningProcesses 调用系统 tasklist /FO CSV /NH 获取当前运行中的去重并按字母排序的 .exe 进程名列表。
func ListRunningProcesses(ctx context.Context) ([]string, error) {
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "tasklist", "/FO", "CSV", "/NH")
	configurePlatformCmd(cmd)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("execute tasklist: %w", err)
	}
	return ParseTasklistCSV(bytes.NewReader(out))
}

// ParseTasklistCSV 解析 tasklist /FO CSV /NH 输出，过滤无关系统基础进程与自身进程，并去重排序。
func ParseTasklistCSV(r io.Reader) ([]string, error) {
	selfExe := strings.ToLower(filepath.Base(os.Args[0]))

	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	seen := make(map[string]struct{})
	var result []string

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 跳过偶发的本地化提示行
			continue
		}
		if len(record) == 0 {
			continue
		}
		name := strings.TrimSpace(record[0])
		if !shouldIncludeProcessName(name, selfExe) {
			continue
		}
		lower := strings.ToLower(name)
		if _, exists := seen[lower]; !exists {
			seen[lower] = struct{}{}
			result = append(result, name)
		}
	}

	slices.SortFunc(result, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	if result == nil {
		result = []string{}
	}
	return result, nil
}
