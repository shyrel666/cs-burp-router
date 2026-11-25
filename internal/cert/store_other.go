//go:build !windows

package cert

import "errors"

var errUnsupportedOS = errors.New("系统根证书自动管理仅支持 Windows 环境，请下载 .der 手动导入")

type noopStore struct{}

// NewSystemStore 在非 Windows 平台返回安全降级实现。
func NewSystemStore() Store {
	return noopStore{}
}

func (noopStore) Inspect(fingerprintSHA1 string) (bool, []string, int, error) {
	return false, nil, 0, nil
}

func (noopStore) InstallRootCA(rawDER []byte, preferMachine bool) (string, error) {
	return "", errUnsupportedOS
}

func (noopStore) RemoveBurpCAs(fingerprintSHA1 string, isAdmin bool) (int, string, error) {
	return 0, "", errUnsupportedOS
}
