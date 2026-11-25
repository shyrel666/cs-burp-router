//go:build windows

package bridge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const processQueryLimitedInformation = 0x1000

var (
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")

	modUser32                    = syscall.NewLazyDLL("user32.dll")
	procEnumWindows              = modUser32.NewProc("EnumWindows")
	procIsWindowVisible          = modUser32.NewProc("IsWindowVisible")
	procGetWindowTextLengthW     = modUser32.NewProc("GetWindowTextLengthW")
	procGetWindowTextW           = modUser32.NewProc("GetWindowTextW")
	procGetWindowThreadProcessId = modUser32.NewProc("GetWindowThreadProcessId")

	modVersion                 = syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSize = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = modVersion.NewProc("VerQueryValueW")
)

var ignoredWindowTitles = map[string]struct{}{
	"default ime":              {},
	"msctfime ui":              {},
	"program manager":          {},
	"windows input experience": {},
}

var (
	winEnumOnce   sync.Once
	winEnumCb     uintptr
	winEnumMu     sync.Mutex
	activeWinDest map[uint32]string

	descCacheMu sync.Mutex
	descCache   = make(map[string]string)
)

func collectVisibleWindowTitles() map[uint32]string {
	winEnumOnce.Do(func() {
		winEnumCb = syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
			vis, _, _ := procIsWindowVisible.Call(hwnd)
			if vis == 0 {
				return 1
			}
			tLen, _, _ := procGetWindowTextLengthW.Call(hwnd)
			if tLen == 0 {
				return 1
			}
			bufLen := int(tLen) + 1
			if bufLen > 256 {
				bufLen = 256
			}
			buf := make([]uint16, bufLen)
			n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(bufLen))
			if n == 0 {
				return 1
			}
			title := strings.TrimSpace(syscall.UTF16ToString(buf[:n]))
			if title == "" {
				return 1
			}
			if _, skip := ignoredWindowTitles[strings.ToLower(title)]; skip {
				return 1
			}

			var pid uint32
			procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
			if pid == 0 {
				return 1
			}
			// 同一 PID 存在多个可见窗口时保留标题更具体（更长）的主窗口名称
			if prev, exists := activeWinDest[pid]; !exists || len([]rune(title)) > len([]rune(prev)) {
				activeWinDest[pid] = title
			}
			return 1
		})
	})

	winEnumMu.Lock()
	defer winEnumMu.Unlock()

	out := make(map[uint32]string, 32)
	activeWinDest = out
	_, _, _ = procEnumWindows.Call(winEnumCb, 0)
	activeWinDest = nil
	return out
}

func queryProcessImagePath(pid uint32) string {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r1, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 || size == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

func cachedExecutableDescription(exePath string) string {
	if exePath == "" {
		return ""
	}
	key := strings.ToLower(exePath)

	descCacheMu.Lock()
	if cached, ok := descCache[key]; ok {
		descCacheMu.Unlock()
		return cached
	}
	descCacheMu.Unlock()

	desc := readPEFileDescription(exePath)

	descCacheMu.Lock()
	if len(descCache) >= 512 {
		clear(descCache)
	}
	descCache[key] = desc
	descCacheMu.Unlock()
	return desc
}

func readPEFileDescription(exePath string) string {
	pathPtr, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return ""
	}
	var handle uint32
	verSize, _, _ := procGetFileVersionInfoSize.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if verSize == 0 || verSize > 4*1024*1024 {
		return ""
	}

	verData := make([]byte, verSize)
	ok, _, _ := procGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		verSize,
		uintptr(unsafe.Pointer(&verData[0])),
	)
	if ok == 0 {
		return ""
	}

	langCodes := extractTranslationCodes(verData)
	baseName := strings.TrimSuffix(filepath.Base(exePath), filepath.Ext(exePath))

	for _, field := range []string{"FileDescription", "ProductName"} {
		for _, code := range langCodes {
			val := queryVersionString(verData, fmt.Sprintf(`\StringFileInfo\%s\%s`, code, field))
			val = strings.TrimSpace(val)
			if val == "" {
				continue
			}
			// 过滤与裸进程名完全一致的无意义占位描述
			if strings.EqualFold(val, filepath.Base(exePath)) || strings.EqualFold(val, baseName) {
				continue
			}
			return val
		}
	}
	return ""
}

func extractTranslationCodes(verData []byte) []string {
	seen := make(map[string]struct{}, 8)
	var codes []string
	addCode := func(c string) {
		lower := strings.ToLower(c)
		if _, exists := seen[lower]; !exists {
			seen[lower] = struct{}{}
			codes = append(codes, lower)
		}
	}

	subBlock, err := syscall.UTF16PtrFromString(`\VarFileInfo\Translation`)
	if err == nil {
		var ptr *uint16
		var byteLen uint32
		r1, _, _ := procVerQueryValue.Call(
			uintptr(unsafe.Pointer(&verData[0])),
			uintptr(unsafe.Pointer(subBlock)),
			uintptr(unsafe.Pointer(&ptr)),
			uintptr(unsafe.Pointer(&byteLen)),
		)
		if r1 != 0 && ptr != nil && byteLen >= 4 {
			raw := unsafe.Slice(ptr, int(byteLen/2))
			for i := 0; i+1 < len(raw); i += 2 {
				addCode(fmt.Sprintf("%04x%04x", raw[i], raw[i+1]))
			}
		}
		runtime.KeepAlive(verData)
		runtime.KeepAlive(subBlock)
	}

	// 常见中文/英文 PE 版本资源回退代码页
	for _, fallback := range []string{"080404b0", "040904b0", "040904e4", "080403a8", "000004b0"} {
		addCode(fallback)
	}
	return codes
}

func queryVersionString(verData []byte, subBlockPath string) string {
	subPtr, err := syscall.UTF16PtrFromString(subBlockPath)
	if err != nil {
		return ""
	}
	var valPtr *uint16
	var charLen uint32
	r1, _, _ := procVerQueryValue.Call(
		uintptr(unsafe.Pointer(&verData[0])),
		uintptr(unsafe.Pointer(subPtr)),
		uintptr(unsafe.Pointer(&valPtr)),
		uintptr(unsafe.Pointer(&charLen)),
	)
	if r1 == 0 || valPtr == nil || charLen == 0 {
		return ""
	}
	if charLen > 512 {
		charLen = 512
	}
	s := syscall.UTF16ToString(unsafe.Slice(valPtr, int(charLen)))
	runtime.KeepAlive(verData)
	runtime.KeepAlive(subPtr)
	return s
}

func listRunningProcessDetailsPlatform(ctx context.Context) ([]ProcessInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		// 极端受限环境下退回 tasklist 文本解析
		names, fbErr := ListRunningProcesses(ctx)
		if fbErr != nil {
			return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
		}
		items := make([]ProcessInfo, 0, len(names))
		for _, n := range names {
			items = append(items, ProcessInfo{Name: n})
		}
		return items, nil
	}
	defer syscall.CloseHandle(snap)

	winTitles := collectVisibleWindowTitles()
	selfExe := strings.ToLower(filepath.Base(os.Args[0]))

	type procAgg struct {
		name        string
		exePath     string
		windowTitle string
		hasWindow   bool
	}
	grouped := make(map[string]*procAgg, 64)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := syscall.Process32First(snap, &pe); err != nil {
		return []ProcessInfo{}, nil
	}

	for {
		name := strings.TrimSpace(syscall.UTF16ToString(pe.ExeFile[:]))
		if shouldIncludeProcessName(name, selfExe) {
			lower := strings.ToLower(name)
			agg, exists := grouped[lower]
			if !exists {
				agg = &procAgg{name: name}
				grouped[lower] = agg
			}
			if agg.exePath == "" && pe.ProcessID != 0 {
				agg.exePath = queryProcessImagePath(pe.ProcessID)
			}
			if title, ok := winTitles[pe.ProcessID]; ok && title != "" {
				agg.hasWindow = true
				if agg.windowTitle == "" || len([]rune(title)) > len([]rune(agg.windowTitle)) {
					agg.windowTitle = title
				}
			}
		}

		pe.Size = uint32(unsafe.Sizeof(pe))
		if err := syscall.Process32Next(snap, &pe); err != nil {
			break
		}
	}

	items := make([]ProcessInfo, 0, len(grouped))
	for _, agg := range grouped {
		desc := cachedExecutableDescription(agg.exePath)
		items = append(items, ProcessInfo{
			Name:        agg.name,
			Description: desc,
			WindowTitle: agg.windowTitle,
			HasWindow:   agg.hasWindow,
		})
	}

	SortProcessDetails(items)
	return items, nil
}
