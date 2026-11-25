package bridge

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// ProcessInfo 描述单个去重后运行进程的展示信息（含应用描述与可见主窗口标题，辅助区分主进程与后台守护进程）。
type ProcessInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	WindowTitle string `json:"windowTitle,omitempty"`
	HasWindow   bool   `json:"hasWindow,omitempty"`
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

// SortProcessDetails 将拥有可见前台窗口的桌面应用排在前列，其余按进程名大小写不敏感字母序排列。
func SortProcessDetails(items []ProcessInfo) {
	slices.SortFunc(items, func(a, b ProcessInfo) int {
		if a.HasWindow != b.HasWindow {
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
