package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxProfileRules      = 256
	maxProfileFieldBytes = 8191
)

// Profile 严格对应 ProxyBridge .pbprofile 配置文件的顶层 JSON 结构。
type Profile struct {
	Version                 string        `json:"Version"`
	Name                    string        `json:"Name"`
	IsTrafficLoggingEnabled bool          `json:"IsTrafficLoggingEnabled"`
	AutoClearConnectionLogs bool          `json:"AutoClearConnectionLogs"`
	LogEveryConnection      bool          `json:"LogEveryConnection"`
	Language                string        `json:"Language"`
	CloseToTray             bool          `json:"CloseToTray"`
	FontZoom                int           `json:"FontZoom"`
	NextProxyConfigId       int           `json:"NextProxyConfigId"`
	ProxyConfigs            []ProxyConfig `json:"ProxyConfigs"`
	ProxyRules              []ProxyRule   `json:"ProxyRules"`
	LogFilters              []any         `json:"LogFilters"`
}

// ProxyConfig 对应 ProxyConfigs 数组元素；注意 Port 必须序列化为 JSON 字符串。
type ProxyConfig struct {
	Id                int    `json:"Id"`
	Name              string `json:"Name"`
	Type              string `json:"Type"`
	Host              string `json:"Host"`
	Port              string `json:"Port"`
	Username          string `json:"Username"`
	Password          string `json:"Password"`
	SendDomainToProxy bool   `json:"SendDomainToProxy"`
}

// ProxyRule 对应 ProxyRules 数组中的单进程代理劫持规则。
type ProxyRule struct {
	Name              string `json:"Name"`
	ProcessName       string `json:"ProcessName"`
	TargetHosts       string `json:"TargetHosts"`
	TargetPorts       string `json:"TargetPorts"`
	TargetDomains     string `json:"TargetDomains"`
	Protocol          string `json:"Protocol"`
	Action            string `json:"Action"`
	IsEnabled         bool   `json:"IsEnabled"`
	LocalhostViaProxy bool   `json:"LocalhostViaProxy"`
	ProxyConfigId     int    `json:"ProxyConfigId"`
}

// ProfileOptions 定义生成运行时 .pbprofile 所需的参数。
type ProfileOptions struct {
	// SocksAddr 为本地 SOCKS5 服务真实监听地址（host:port）。
	SocksAddr string
	// Processes 为需要被劫持代理的目标进程名列表（如 ["client.exe", "java.exe"]）。
	Processes []string
	// TargetDomains 为规则的 TargetDomains 值；为 nil 时默认使用 "*"，也可显式传入空字符串指针 "" 适配纯 IP 流量。
	TargetDomains *string
}

// BuildProfile 根据当前 SOCKS5 监听地址和目标进程列表构造符合契约的 Profile 对象。
func BuildProfile(opts ProfileOptions) (Profile, error) {
	host, portStr, err := parseSocksEndpoint(opts.SocksAddr)
	if err != nil {
		return Profile{}, fmt.Errorf("invalid socks5 address %q: %w", opts.SocksAddr, err)
	}

	cleanedProcs, err := NormalizeProcessList(opts.Processes)
	if err != nil {
		return Profile{}, err
	}

	targetDomains := "*"
	if opts.TargetDomains != nil {
		targetDomains = *opts.TargetDomains
	}
	if len(targetDomains) > maxProfileFieldBytes {
		return Profile{}, fmt.Errorf("target domains exceed the ProxyBridge limit of %d bytes", maxProfileFieldBytes)
	}

	rules := make([]ProxyRule, 0, len(cleanedProcs))
	for _, proc := range cleanedProcs {
		rules = append(rules, ProxyRule{
			Name:              "Route " + proc,
			ProcessName:       proc,
			TargetHosts:       "*",
			TargetPorts:       "*",
			TargetDomains:     targetDomains,
			Protocol:          "TCP",
			Action:            "PROXY",
			IsEnabled:         true,
			LocalhostViaProxy: false,
			ProxyConfigId:     1,
		})
	}

	return Profile{
		Version:                 "1.0",
		Name:                    "CS-Burp-Router Runtime Profile",
		IsTrafficLoggingEnabled: true,
		AutoClearConnectionLogs: true,
		LogEveryConnection:      false,
		Language:                "en",
		CloseToTray:             true,
		FontZoom:                100,
		NextProxyConfigId:       2,
		ProxyConfigs: []ProxyConfig{
			{
				Id:                1,
				Name:              "CS-Burp-Router Local SOCKS5",
				Type:              "SOCKS5",
				Host:              host,
				Port:              portStr,
				Username:          "",
				Password:          "",
				SendDomainToProxy: targetDomains != "",
			},
		},
		ProxyRules: rules,
		LogFilters: []any{},
	}, nil
}

// WriteTempProfile 将 Profile 序列化写入临时目录下的 .pbprofile 文件并返回其绝对路径。
func WriteTempProfile(tempDir string, profile Profile) (string, error) {
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	encoder.SetIndent("", "  ")
	// ProxyBridge 4.3.0 does not decode Unicode escapes in profile strings.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(profile); err != nil {
		return "", fmt.Errorf("marshal pbprofile: %w", err)
	}

	f, err := os.CreateTemp(tempDir, "cs-burp-router-*.pbprofile")
	if err != nil {
		return "", fmt.Errorf("create temp pbprofile: %w", err)
	}
	path := f.Name()

	if _, err := f.Write(data.Bytes()); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write temp pbprofile: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("sync temp pbprofile: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close temp pbprofile: %w", err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return absPath, nil
}

// NormalizeProcessList 清洗、校验并按大小写不敏感去重目标进程名列表，同时禁止劫持自身或 ProxyBridge 进程。
func NormalizeProcessList(processes []string) ([]string, error) {
	selfExe := strings.ToLower(filepath.Base(os.Args[0]))
	seen := make(map[string]struct{}, len(processes))
	out := make([]string, 0, len(processes))

	for _, raw := range processes {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".exe") ||
			!utf8.ValidString(name) || len(utf16.Encode([]rune(name))) > 255 ||
			strings.ContainsAny(name, "<>:\"/\\|?*,;\u2028\u2029") || strings.ContainsFunc(name, unicode.IsControl) {
			return nil, fmt.Errorf("expected a literal Windows executable name, got %q", name)
		}
		if lower == "proxybridge_cli.exe" || lower == "proxybridge.exe" || (selfExe != "" && lower == selfExe) {
			return nil, fmt.Errorf("cannot hijack router or ProxyBridge process itself: %s", name)
		}
		if _, exists := seen[lower]; !exists {
			seen[lower] = struct{}{}
			out = append(out, name)
		}
	}

	if len(out) == 0 {
		return nil, errors.New("processes list cannot be empty")
	}
	if len(out) > maxProfileRules {
		return nil, fmt.Errorf("processes list exceeds the ProxyBridge limit of %d rules", maxProfileRules)
	}
	return out, nil
}

func parseSocksEndpoint(addr string) (string, string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", "", err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", "", errors.New("port must be between 1 and 65535")
	}

	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return host, strconv.Itoa(portNum), nil
}
