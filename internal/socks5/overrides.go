package socks5

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// OverrideRule 表示单条针对 host:port 或 host 的强制路由覆盖规则。
type OverrideRule struct {
	Target string      `json:"target"`
	Action RouteAction `json:"action"`
}

// ValidateOverrideAction 校验覆盖规则动作（仅允许 Direct 或 Burp）。
func ValidateOverrideAction(action RouteAction) error {
	switch action {
	case ActionDirect, ActionBurp:
		return nil
	default:
		return fmt.Errorf("invalid override action %q: must be Direct or Burp", action)
	}
}

// NormalizeOverrideTarget 规范化覆盖规则目标，支持精确 host:port 或按 host 匹配（兼容 IPv4 / IPv6 / 域名）。
func NormalizeOverrideTarget(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("target cannot be empty")
	}
	for i := 0; i < len(trimmed); i++ {
		b := trimmed[i]
		if b <= 0x20 || b == 0x7f || b == '/' || b == '\\' {
			return "", fmt.Errorf("invalid character in target %q", raw)
		}
	}

	// 1. 纯 IP（IPv4 或未加方括号的 IPv6，不含端口）
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String(), nil
	}

	// 2. 带方括号但无端口的 IPv6（如 [2001:db8::1]）
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		inner := trimmed[1 : len(trimmed)-1]
		if ip := net.ParseIP(inner); ip != nil {
			return ip.String(), nil
		}
		return "", fmt.Errorf("invalid bracketed host %q", raw)
	}

	// 3. host:port 形式
	if host, portStr, err := net.SplitHostPort(trimmed); err == nil {
		normHost := normalizeHost(host)
		if normHost == "" {
			return "", fmt.Errorf("empty host in target %q", raw)
		}
		if portStr == "" || strings.HasPrefix(portStr, "+") || strings.HasPrefix(portStr, "-") {
			return "", fmt.Errorf("invalid port in target %q", raw)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("port out of range in target %q: must be 1-65535", raw)
		}
		return net.JoinHostPort(normHost, strconv.Itoa(port)), nil
	}

	// 包含冒号但既不是合法纯 IP 也不是合法 host:port，则视为非法地址
	if strings.Contains(trimmed, ":") {
		return "", fmt.Errorf("invalid host:port target %q", raw)
	}

	// 4. 纯域名 host
	normHost := normalizeHost(trimmed)
	if normHost == "" {
		return "", fmt.Errorf("invalid target %q", raw)
	}
	return normHost, nil
}

// matchOverrideMap 按「精确 host:port > host」优先级在规则表中查找覆盖动作。
func matchOverrideMap(rules map[string]RouteAction, targetHost string, targetPort uint16) (RouteAction, bool) {
	if len(rules) == 0 {
		return "", false
	}
	normHost := normalizeHost(targetHost)
	if normHost == "" {
		return "", false
	}
	exactKey := net.JoinHostPort(normHost, strconv.Itoa(int(targetPort)))
	if act, ok := rules[exactKey]; ok {
		return act, true
	}
	if act, ok := rules[normHost]; ok {
		return act, true
	}
	return "", false
}

func listOverrideMap(rules map[string]RouteAction) []OverrideRule {
	out := make([]OverrideRule, 0, len(rules))
	for target, action := range rules {
		out = append(out, OverrideRule{
			Target: target,
			Action: action,
		})
	}
	slices.SortFunc(out, func(a, b OverrideRule) int {
		return strings.Compare(a.Target, b.Target)
	})
	return out
}

// OverrideStore 是并发安全的独立覆盖规则表（可供无 SOCKS5 实例的独立 Web 看板模式复用）。
type OverrideStore struct {
	mu    sync.RWMutex
	rules map[string]RouteAction
}

// NewOverrideStore 创建空的并发安全覆盖规则表。
func NewOverrideStore() *OverrideStore {
	return &OverrideStore{
		rules: make(map[string]RouteAction),
	}
}

// Set 添加或更新单条覆盖规则，返回规范化后的规则。
func (st *OverrideStore) Set(target string, action RouteAction) (OverrideRule, error) {
	normTarget, err := NormalizeOverrideTarget(target)
	if err != nil {
		return OverrideRule{}, err
	}
	if err := ValidateOverrideAction(action); err != nil {
		return OverrideRule{}, err
	}
	st.mu.Lock()
	st.rules[normTarget] = action
	st.mu.Unlock()
	return OverrideRule{Target: normTarget, Action: action}, nil
}

// Delete 移除指定目标的覆盖规则，返回是否存在并已移除。
func (st *OverrideStore) Delete(target string) (bool, error) {
	normTarget, err := NormalizeOverrideTarget(target)
	if err != nil {
		return false, err
	}
	st.mu.Lock()
	_, existed := st.rules[normTarget]
	delete(st.rules, normTarget)
	st.mu.Unlock()
	return existed, nil
}

// Clear 清空全部覆盖规则。
func (st *OverrideStore) Clear() {
	st.mu.Lock()
	clear(st.rules)
	st.mu.Unlock()
}

// List 返回按目标升序排列的全部覆盖规则副本。
func (st *OverrideStore) List() []OverrideRule {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return listOverrideMap(st.rules)
}

// Match 按「精确 host:port > host」查找目标是否命中覆盖规则。
func (st *OverrideStore) Match(targetHost string, targetPort uint16) (RouteAction, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return matchOverrideMap(st.rules, targetHost, targetPort)
}
