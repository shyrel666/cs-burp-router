package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildProfileJSONSchemaAndTypes(t *testing.T) {
	prof, err := BuildProfile(ProfileOptions{
		SocksAddr: "127.0.0.1:10808",
		Processes: []string{"client.exe", "java.exe", "CLIENT.EXE"}, // 含大小写重复项
	})
	if err != nil {
		t.Fatalf("BuildProfile error: %v", err)
	}

	rawJSON, err := json.Marshal(prof)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	// 反序列化到无类型 map 以严格校验 JSON 字段名及动态类型（特别是 Port 必须为 string）
	var doc map[string]any
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		t.Fatalf("json.Unmarshal to map: %v", err)
	}

	if doc["Version"] != "1.0" {
		t.Fatalf("Version = %v, want 1.0", doc["Version"])
	}

	cfgs, ok := doc["ProxyConfigs"].([]any)
	if !ok || len(cfgs) != 1 {
		t.Fatalf("ProxyConfigs invalid: %v", doc["ProxyConfigs"])
	}
	cfg0 := cfgs[0].(map[string]any)
	if cfg0["Type"] != "SOCKS5" {
		t.Fatalf("ProxyConfigs[0].Type = %v, want SOCKS5", cfg0["Type"])
	}
	if cfg0["Host"] != "127.0.0.1" {
		t.Fatalf("ProxyConfigs[0].Host = %v, want 127.0.0.1", cfg0["Host"])
	}
	portVal, portIsString := cfg0["Port"].(string)
	if !portIsString || portVal != "10808" {
		t.Fatalf("ProxyConfigs[0].Port must be string \"10808\", got (%T) %v", cfg0["Port"], cfg0["Port"])
	}
	sendDomain, ok := cfg0["SendDomainToProxy"].(bool)
	if !ok || !sendDomain {
		t.Fatalf("ProxyConfigs[0].SendDomainToProxy = %v, want true", cfg0["SendDomainToProxy"])
	}

	rules, ok := doc["ProxyRules"].([]any)
	if !ok || len(rules) != 2 {
		t.Fatalf("expected 2 deduplicated ProxyRules, got %v", doc["ProxyRules"])
	}

	wantProcs := []string{"client.exe", "java.exe"}
	for i, rAny := range rules {
		r := rAny.(map[string]any)
		if r["ProcessName"] != wantProcs[i] {
			t.Fatalf("rule[%d].ProcessName = %v, want %s", i, r["ProcessName"], wantProcs[i])
		}
		if r["Protocol"] != "TCP" || r["Action"] != "PROXY" {
			t.Fatalf("rule[%d] unexpected Protocol/Action: %v", i, r)
		}
		if r["IsEnabled"] != true {
			t.Fatalf("rule[%d].IsEnabled = %v, want true", i, r["IsEnabled"])
		}
		localhostViaProxy, isBool := r["LocalhostViaProxy"].(bool)
		if !isBool || localhostViaProxy != false {
			t.Fatalf("rule[%d].LocalhostViaProxy = %v, want false", i, r["LocalhostViaProxy"])
		}
		if r["ProxyConfigId"] != float64(1) {
			t.Fatalf("rule[%d].ProxyConfigId = %v, want 1", i, r["ProxyConfigId"])
		}
		if r["TargetHosts"] != "*" || r["TargetPorts"] != "*" || r["TargetDomains"] != "*" {
			t.Fatalf("rule[%d] unexpected target wildcards: %v", i, r)
		}
	}

	// 验证显式将 TargetDomains 设为空字符串 ""（适配纯 IP 流量场景）
	emptyDomains := ""
	ipProf, err := BuildProfile(ProfileOptions{
		SocksAddr:     "0.0.0.0:19080",
		Processes:     []string{"app.exe"},
		TargetDomains: &emptyDomains,
	})
	if err != nil {
		t.Fatalf("BuildProfile with empty TargetDomains: %v", err)
	}
	if ipProf.ProxyConfigs[0].Host != "127.0.0.1" || ipProf.ProxyConfigs[0].Port != "19080" {
		t.Fatalf("wildcard listen host normalization failed: %+v", ipProf.ProxyConfigs[0])
	}
	if ipProf.ProxyRules[0].TargetDomains != "" {
		t.Fatalf("expected TargetDomains == \"\", got %q", ipProf.ProxyRules[0].TargetDomains)
	}
	if ipProf.ProxyConfigs[0].SendDomainToProxy {
		t.Fatal("IP mode must send IP addresses to SOCKS5")
	}

	// 验证禁止劫持 ProxyBridge_CLI.exe 自身
	if _, err := BuildProfile(ProfileOptions{
		SocksAddr: "127.0.0.1:10808",
		Processes: []string{"ProxyBridge_CLI.exe"},
	}); err == nil {
		t.Fatal("expected error when attempting to hijack ProxyBridge_CLI.exe")
	}
}

func TestProfileLimitsAndLiteralExecutableNames(t *testing.T) {
	const socksAddr = "127.0.0.1:10808"
	for _, name := range []string{
		"*", "tool*.exe", "ANY", "app\x00.exe", "script.cmd", "one.exe;two.exe", "one.exe,two.exe",
		`C:\Program Files\app.exe`, `C:app.exe`, `folder\app.exe`, `folder/app.exe`, `app.exe\`, `..\app.exe`,
	} {
		if _, err := NormalizeProcessList([]string{name}); err == nil {
			t.Errorf("NormalizeProcessList(%q) accepted a nonliteral executable name", name)
		}
	}
	valid, err := NormalizeProcessList([]string{"  客户端 Test+.EXE  ", ".exe", "R&D.exe"})
	if err != nil || len(valid) != 3 || valid[0] != "客户端 Test+.EXE" || valid[1] != ".exe" || valid[2] != "R&D.exe" {
		t.Fatalf("NormalizeProcessList changed literal names: %q, %v", valid, err)
	}

	processes := make([]string, 0, maxProfileRules+1)
	for n := 0; n < maxProfileRules; n++ {
		processes = append(processes, fmt.Sprintf("app%d.exe", n))
	}
	if _, err := NormalizeProcessList(append(processes, "APP0.EXE")); err != nil {
		t.Fatalf("duplicate should not count against the rule limit: %v", err)
	}
	if _, err := NormalizeProcessList(append(processes, "extra.exe")); err == nil {
		t.Fatal("selection exceeding the CLI rule limit was accepted")
	}

	prof, err := BuildProfile(ProfileOptions{SocksAddr: socksAddr, Processes: []string{"R&D.exe"}})
	if err != nil {
		t.Fatal(err)
	}
	path, err := WriteTempProfile(t.TempDir(), prof)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"ProcessName": "R&D.exe"`) {
		t.Fatalf("CLI profile did not preserve the literal executable name: %s", data)
	}
}

// mockManagedProcess 用于无外部依赖地模拟子进程生命周期、优雅退出、卡死强杀及日志输出。
type mockManagedProcess struct {
	pid            int
	stdoutR        *io.PipeReader
	stdoutW        *io.PipeWriter
	stderrR        *io.PipeReader
	stderrW        *io.PipeWriter
	ignoreTerm     bool
	killed         atomic.Bool
	exitCh         chan error
	closePipesOnce sync.Once
}

func newMockManagedProcess(pid int, ignoreTerm bool) *mockManagedProcess {
	outR, outW := io.Pipe()
	errR, errW := io.Pipe()
	return &mockManagedProcess{
		pid:        pid,
		stdoutR:    outR,
		stdoutW:    outW,
		stderrR:    errR,
		stderrW:    errW,
		ignoreTerm: ignoreTerm,
		exitCh:     make(chan error, 1),
	}
}

func (p *mockManagedProcess) closePipes() {
	p.closePipesOnce.Do(func() {
		_ = p.stdoutW.Close()
		_ = p.stderrW.Close()
	})
}

func (p *mockManagedProcess) PID() int          { return p.pid }
func (p *mockManagedProcess) Stdout() io.Reader { return p.stdoutR }
func (p *mockManagedProcess) Stderr() io.Reader { return p.stderrR }

func (p *mockManagedProcess) Terminate() error {
	if p.ignoreTerm {
		return nil
	}
	p.closePipes()
	select {
	case p.exitCh <- nil:
	default:
	}
	return nil
}

func (p *mockManagedProcess) Kill() error {
	p.killed.Store(true)
	p.closePipes()
	select {
	case p.exitCh <- errors.New("killed"):
	default:
	}
	return nil
}

func (p *mockManagedProcess) Wait() error {
	return <-p.exitCh
}

func TestManagerLifecycleDuplicateStartRestartAndLogs(t *testing.T) {
	tempDir := t.TempDir()
	var nextPID atomic.Int32
	nextPID.Store(2000)

	var (
		mu          sync.Mutex
		spawnedArgs [][]string
		lastProc    *mockManagedProcess
		hangOnTerm  bool
	)

	mockRunner := func(binaryPath string, args []string) (ManagedProcess, error) {
		// 启动瞬间验证临时 .pbprofile 文件已写入磁盘且内容合法
		if len(args) != 4 || args[0] != "--profile" || args[2] != "--verbose" || args[3] != "3" {
			return nil, fmt.Errorf("unexpected CLI args: %v", args)
		}
		if _, err := os.Stat(args[1]); err != nil {
			return nil, fmt.Errorf("profile file missing on start: %w", err)
		}

		pid := int(nextPID.Add(1))
		mu.Lock()
		ignore := hangOnTerm
		proc := newMockManagedProcess(pid, ignore)
		spawnedArgs = append(spawnedArgs, append([]string(nil), args...))
		lastProc = proc
		mu.Unlock()

		// 写入超过 200 行的日志流，验证环形缓冲截断与无竞态读取
		go func(mp *mockManagedProcess) {
			for i := 1; i <= 230; i++ {
				_, _ = fmt.Fprintf(mp.stdoutW, "conn event line %d\n", i)
			}
			_, _ = fmt.Fprintf(mp.stderrW, "engine ready for pid %d\n", pid)
		}(proc)

		return proc, nil
	}

	mgr := NewManager(ManagerConfig{
		SocksAddr:        "127.0.0.1:10808",
		TempDir:          tempDir,
		StopTimeout:      80 * time.Millisecond,
		LogCapacity:      200,
		Runner:           mockRunner,
		AdminChecker:     func() bool { return false },
		SkipBinaryLookup: true,
	})

	// 1. 正常启动
	if err := mgr.Start([]string{"client.exe", "java.exe"}); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	st1 := mgr.Status()
	if st1.State != StateRunning || st1.PID != 2001 {
		t.Fatalf("unexpected status after Start: %+v", st1)
	}
	firstProfile := st1.ProfilePath

	// 2. 重复调用 Start 必须返回 ErrAlreadyRunning 且不得额外拉起进程
	if err := mgr.Start([]string{"other.exe"}); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("duplicate Start error = %v, want ErrAlreadyRunning", err)
	}

	// 3. 热重启 Restart：应优雅终止旧进程、删除旧临时文件并生成新配置启动新 PID
	mu.Lock()
	hangOnTerm = true // 让新拉起的第二个进程忽略优雅终止，以同时测试后续 Stop 超时强杀逻辑
	mu.Unlock()

	if err := mgr.Restart([]string{"navicat.exe"}); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	if _, err := os.Stat(firstProfile); !os.IsNotExist(err) {
		t.Fatalf("old temp profile %s was not cleaned up on Restart", firstProfile)
	}

	st2 := mgr.Status()
	if st2.State != StateRunning || st2.PID != 2002 || len(st2.Processes) != 1 || st2.Processes[0] != "navicat.exe" {
		t.Fatalf("unexpected status after Restart: %+v", st2)
	}
	secondProfile := st2.ProfilePath

	// 等待异步日志流写入完成并并发调用 Status() 检查无数据竞争
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s := mgr.Status()
		if len(s.Logs) == 200 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gotLines := len(mgr.Status().Logs); gotLines != 200 {
		t.Fatalf("expected log ring buffer capped at 200 lines, got %d", gotLines)
	}

	// 4. 调用 Stop：第二个进程忽略 Terminate，应在 80ms 超时后触发强杀 Kill 并清理临时文件
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	mu.Lock()
	secondProc := lastProc
	mu.Unlock()
	if !secondProc.killed.Load() {
		t.Fatal("expected hung process to be force-killed after StopTimeout")
	}
	if _, err := os.Stat(secondProfile); !os.IsNotExist(err) {
		t.Fatalf("second temp profile %s was not cleaned up on Stop", secondProfile)
	}

	stFinal := mgr.Status()
	if stFinal.State != StateStopped || stFinal.PID != 0 {
		t.Fatalf("unexpected status after Stop: %+v", stFinal)
	}
}

func TestWindowsDefaultRunnerRequiresAdminBeforeChangingState(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows CLI elevation requirement")
	}
	tempDir := t.TempDir()
	isAdmin := false
	mgr := NewManager(ManagerConfig{
		TempDir:          tempDir,
		AdminChecker:     func() bool { return isAdmin },
		SkipBinaryLookup: true,
	})
	var starts int
	mgr.runner = func(string, []string) (ManagedProcess, error) {
		starts++
		return newMockManagedProcess(starts, false), nil
	}
	mgr.waitForReady = false
	t.Cleanup(func() { _ = mgr.Shutdown() })

	if err := mgr.Start([]string{"app.exe"}); !errors.Is(err, ErrAdminRequired) {
		t.Fatalf("Start without elevation = %v", err)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 || starts != 0 {
		t.Fatalf("failed Start changed state: %v profiles, %d runner calls, %v", entries, starts, err)
	}

	isAdmin = true
	if err := mgr.Start([]string{"app.exe"}); err != nil {
		t.Fatal(err)
	}
	running := mgr.Status()
	isAdmin = false
	if err := mgr.Restart([]string{"another.exe"}); !errors.Is(err, ErrAdminRequired) {
		t.Fatalf("Restart without elevation = %v", err)
	}
	if after := mgr.Status(); after.State != StateRunning || after.PID != running.PID || after.ProfilePath != running.ProfilePath {
		t.Fatalf("refused Restart changed running instance: %+v", after)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 1 || starts != 1 {
		t.Fatalf("refused Restart changed state: %v profiles, %d runner calls, %v", entries, starts, err)
	}
}

func TestManagerWaitsForReadinessAndShutsDownPermanently(t *testing.T) {
	p := newMockManagedProcess(123, false)
	mgr := NewManager(ManagerConfig{
		Runner:           func(string, []string) (ManagedProcess, error) { return p, nil },
		TempDir:          t.TempDir(),
		SkipBinaryLookup: true,
		StartTimeout:     time.Second,
	})
	mgr.waitForReady = true
	t.Cleanup(func() { _ = mgr.Shutdown() })
	startDone := make(chan error, 1)
	go func() { startDone <- mgr.Start([]string{"app.exe"}) }()
	if _, err := fmt.Fprintln(p.stdoutW, "Loading profile"); err != nil {
		t.Fatal(err)
	}
	if got := mgr.Status().State; got != StateStarting {
		t.Fatalf("state before readiness = %s, want Starting", got)
	}
	if _, err := fmt.Fprintln(p.stdoutW, "[LOG]  ProxyBridge started"); err != nil {
		t.Fatal(err)
	}
	if err := <-startDone; err != nil || mgr.Status().State != StateRunning {
		t.Fatalf("start after readiness = %v, status %+v", err, mgr.Status())
	}
	if err := mgr.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start([]string{"app.exe"}); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Start after shutdown = %v", err)
	}
	if err := mgr.Restart([]string{"app.exe"}); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Restart after shutdown = %v", err)
	}
}

type unkillableTestProcess struct {
	*mockManagedProcess
	killErr error
}

func (p unkillableTestProcess) Kill() error { return p.killErr }

func TestManagerForcedStopReturnsWithRemainingProcess(t *testing.T) {
	p := unkillableTestProcess{newMockManagedProcess(123, true), errors.New("kill failed")}
	mgr := NewManager(ManagerConfig{
		Runner:           func(string, []string) (ManagedProcess, error) { return p, nil },
		TempDir:          t.TempDir(),
		SkipBinaryLookup: true,
		StopTimeout:      10 * time.Millisecond,
	})
	if err := mgr.Start([]string{"app.exe"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.closePipes()
		p.exitCh <- nil
		_ = mgr.Shutdown()
	})
	if err := mgr.Stop(); !errors.Is(err, p.killErr) {
		t.Fatalf("Stop error = %v, want %v", err, p.killErr)
	}
	if state := mgr.Status(); state.State != StateError || state.PID != p.PID() {
		t.Fatalf("failed stop lost the running process: %+v", state)
	}
	if err := mgr.Start([]string{"app.exe"}); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("Start with a process still owned by the manager = %v", err)
	}
}

func TestParseTasklistCSV(t *testing.T) {
	sample := strings.Join([]string{
		`"System Idle Process","0","Services","0","8 K"`,
		`"svchost.exe","884","Services","0","24,120 K"`,
		`"ProxyBridge_CLI.exe","4120","Console","1","12,000 K"`,
		`"navicat.exe","9012","Console","1","88,400 K"`,
		`"Java.exe","7310","Console","1","210,100 K"`,
		`"navicat.exe","9099","Console","1","45,000 K"`,
		`"apifox.exe","6500","Console","1","160,000 K"`,
	}, "\r\n")

	got, err := ParseTasklistCSV(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("ParseTasklistCSV error: %v", err)
	}
	want := []string{"apifox.exe", "Java.exe", "navicat.exe"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSortAndListRunningProcessDetails(t *testing.T) {
	items := []ProcessInfo{
		{Name: "cloudmusic_reporter.exe"},
		{Name: "zed.exe", HasWindow: true, WindowTitle: "Zed"},
		{Name: "cloudmusic.exe", Description: "NetEase Cloud Music", HasWindow: true, WindowTitle: "网易云音乐"},
		{Name: "apifox.exe", Description: "Apifox"},
	}
	SortProcessDetails(items)

	// 有可见窗口的应用优先，同组内按进程名字母排序
	wantOrder := []string{"cloudmusic.exe", "zed.exe", "apifox.exe", "cloudmusic_reporter.exe"}
	for i, w := range wantOrder {
		if items[i].Name != w {
			t.Fatalf("sorted[%d].Name = %q, want %q", i, items[i].Name, w)
		}
	}

	if runtime.GOOS == "windows" {
		live, err := ListRunningProcessDetails(context.Background())
		if err != nil {
			t.Fatalf("ListRunningProcessDetails error: %v", err)
		}
		if len(live) == 0 {
			t.Fatal("expected non-empty running process details on Windows")
		}
		for _, p := range live {
			lower := strings.ToLower(p.Name)
			if !strings.HasSuffix(lower, ".exe") {
				t.Fatalf("unexpected non-exe process %q", p.Name)
			}
			if lower == "svchost.exe" || lower == "proxybridge_cli.exe" {
				t.Fatalf("ignored process %q leaked into ListRunningProcessDetails", p.Name)
			}
		}
	}
}

func TestWindowsJobObjectAndExecRunner(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific Job Object test")
	}

	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	cmdExe := filepath.Join(sysRoot, "System32", "cmd.exe")

	proc, err := defaultExecRunner(cmdExe, []string{"/c", "echo job-object-ok"})
	if err != nil {
		t.Fatalf("defaultExecRunner failed: %v", err)
	}
	t.Cleanup(func() {
		closeOutput(proc.Stdout())
		closeOutput(proc.Stderr())
	})
	out, err := io.ReadAll(proc.Stdout())
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := proc.Wait(); err != nil {
		t.Fatalf("wait cmd.exe: %v", err)
	}
	if !strings.Contains(string(out), "job-object-ok") {
		t.Fatalf("unexpected stdout: %q", string(out))
	}
}

func TestIsAdminStatusFieldAndChecker(t *testing.T) {
	// 验证真实系统检测调用安全无崩溃，且默认 Manager.Status().IsAdmin 与 IsProcessAdmin() 一致
	realAdmin := IsProcessAdmin()
	defaultMgr := NewManager(ManagerConfig{SkipBinaryLookup: true})
	if defaultMgr.Status().IsAdmin != realAdmin {
		t.Fatalf("default Manager IsAdmin = %v, want %v", defaultMgr.Status().IsAdmin, realAdmin)
	}

	// 验证注入 AdminChecker 为 false / true 时 Status() 及 JSON 序列化字段 is_admin 严格匹配
	for _, wantAdmin := range []bool{false, true} {
		val := wantAdmin
		mgr := NewManager(ManagerConfig{
			SkipBinaryLookup: true,
			AdminChecker:     func() bool { return val },
		})
		snap := mgr.Status()
		if snap.IsAdmin != wantAdmin {
			t.Fatalf("Status().IsAdmin = %v, want %v", snap.IsAdmin, wantAdmin)
		}

		raw, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal StatusSnapshot: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("unmarshal StatusSnapshot map: %v", err)
		}
		gotJSONField, ok := doc["is_admin"].(bool)
		if !ok || gotJSONField != wantAdmin {
			t.Fatalf("JSON field is_admin = (%T)%v, want bool %v", doc["is_admin"], doc["is_admin"], wantAdmin)
		}
	}
}
