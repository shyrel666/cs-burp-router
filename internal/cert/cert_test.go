package cert

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func generateTestCertDER(t *testing.T, commonName string, isCA bool) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	usage := x509.KeyUsageDigitalSignature
	if isCA {
		usage |= x509.KeyUsageCertSign
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20261125),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"PortSwigger"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              usage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create x509 cert: %v", err)
	}
	return der
}

type memCertStore struct {
	mu      sync.Mutex
	machine map[string][]byte
	user    map[string][]byte
}

func newMemCertStore() *memCertStore {
	return &memCertStore{
		machine: make(map[string][]byte),
		user:    make(map[string][]byte),
	}
}

func sha1Hex(raw []byte) string {
	s := sha1.Sum(raw)
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

func (m *memCertStore) Inspect(fingerprintSHA1 string) (bool, []string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := strings.ToUpper(strings.TrimSpace(fingerprintSHA1))
	var scopes []string
	legacy := make(map[string]struct{})

	checkMap := func(scopeName string, certs map[string][]byte) {
		matched := false
		for fp, raw := range certs {
			if want != "" && fp == want {
				matched = true
				legacy[fp] = struct{}{}
				continue
			}
			if c, err := x509.ParseCertificate(raw); err == nil && isPortSwiggerCert(c) {
				legacy[fp] = struct{}{}
			}
		}
		if matched {
			scopes = append(scopes, scopeName)
		}
	}

	checkMap("LocalMachine", m.machine)
	checkMap("CurrentUser", m.user)
	return len(scopes) > 0, scopes, len(legacy), nil
}

func (m *memCertStore) InstallRootCA(rawDER []byte, preferMachine bool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fp := sha1Hex(rawDER)
	cp := append([]byte(nil), rawDER...)
	if preferMachine {
		m.machine[fp] = cp
		return "LocalMachine", nil
	}
	m.user[fp] = cp
	return "CurrentUser", nil
}

func (m *memCertStore) RemoveBurpCAs(fingerprintSHA1 string, isAdmin bool) (int, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := strings.ToUpper(strings.TrimSpace(fingerprintSHA1))
	removed := 0
	var warn string

	cleanMap := func(certs map[string][]byte) {
		for fp, raw := range certs {
			if want != "" && fp == want {
				delete(certs, fp)
				removed++
				continue
			}
			if c, err := x509.ParseCertificate(raw); err == nil && isPortSwiggerCert(c) {
				delete(certs, fp)
				removed++
			}
		}
	}

	if isAdmin {
		cleanMap(m.machine)
	} else if len(m.machine) > 0 {
		warn = "LocalMachine requires admin"
	}
	cleanMap(m.user)
	if warn != "" {
		return removed, warn, ErrCleanupIncomplete
	}
	return removed, warn, nil
}

func TestParseAndValidateCA(t *testing.T) {
	caDER := generateTestCertDER(t, "PortSwigger CA", true)
	parsed, err := ParseAndValidateCA(caDER)
	if err != nil {
		t.Fatalf("ParseAndValidateCA(DER) failed: %v", err)
	}
	if parsed.CommonName != "PortSwigger CA" || parsed.FingerprintSHA1 != sha1Hex(caDER) {
		t.Fatalf("unexpected parsed CA: %+v", parsed)
	}

	// 支持 PEM 自动解码
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	parsedPEM, err := ParseAndValidateCA(pemBytes)
	if err != nil {
		t.Fatalf("ParseAndValidateCA(PEM) failed: %v", err)
	}
	if !bytes.Equal(parsedPEM.RawDER, caDER) {
		t.Fatal("PEM decoded RawDER mismatch")
	}

	// 拒绝非 CA 终端实体证书
	leafDER := generateTestCertDER(t, "example.com", false)
	if _, err := ParseAndValidateCA(leafDER); err == nil {
		t.Fatal("expected non-CA leaf certificate to be rejected")
	}

	// 拒绝普通网页内容
	if _, err := ParseAndValidateCA([]byte("<html>not a cert</html>")); err == nil {
		t.Fatal("expected invalid HTML payload to be rejected")
	}
}

func TestManagerFetchInstallStatusAndUninstall(t *testing.T) {
	caDER := generateTestCertDER(t, "PortSwigger CA", true)
	oldCADER := generateTestCertDER(t, "PortSwigger CA", true)

	// 模拟仅响应代理式请求或标准 /cert 的 Burp Listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock burp cert server: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				if req.URL.Path == "/cert" || req.RequestURI == "http://burp/cert" {
					_, _ = fmt.Fprintf(
						conn,
						"HTTP/1.0 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Length: %d\r\n\r\n",
						len(caDER),
					)
					_, _ = conn.Write(caDER)
					return
				}
				_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()

	store := newMemCertStore()
	// 预置一张旧的不同指纹 PortSwigger 证书，模拟甲方机器存在其他测试人员遗留旧证书的场景
	_, _ = store.InstallRootCA(oldCADER, false)

	isAdmin := true
	mgr := NewManager(ManagerConfig{
		Store:        store,
		AdminChecker: func() bool { return isAdmin },
		FetchTimeout: 2 * time.Second,
	})

	ctx := context.Background()
	burpAddr := ln.Addr().String()

	// 1. 初始状态：旧证书指纹不匹配当前 Burp，因此 Installed 必须为 false，但 LegacyCount == 1
	st0 := mgr.CheckStatus(ctx, burpAddr)
	if !st0.BurpReachable || st0.Installed || st0.LegacyCount != 1 {
		t.Fatalf("unexpected initial status with mismatched legacy cert: %+v", st0)
	}

	// 2. 一键安装当前 Burp 证书（管理员写入 LocalMachine）
	installRes, err := mgr.Install(ctx, burpAddr)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if !installRes.Installed || installRes.ActionScope != "LocalMachine" || installRes.InstalledScope != "LocalMachine" {
		t.Fatalf("unexpected status after admin install: %+v", installRes)
	}

	// 3. 一键撤场卸载：同时清理当前 Burp 证书与历史遗留 PortSwigger CA（共 2 张）
	uninstallRes, err := mgr.Uninstall(ctx, burpAddr)
	if err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	if uninstallRes.RemovedCount != 2 || uninstallRes.Installed || uninstallRes.LegacyCount != 0 {
		t.Fatalf("unexpected status after uninstall: %+v", uninstallRes)
	}
}

func TestInstallVerifiedUsesOnlyTheConfirmedSnapshot(t *testing.T) {
	firstDER := generateTestCertDER(t, "First Burp CA", true)
	secondDER := generateTestCertDER(t, "Second Burp CA", true)
	second, err := ParseAndValidateCA(secondDER)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = w.Write(firstDER)
			return
		}
		_, _ = w.Write(secondDER)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	store := newMemCertStore()
	mgr := NewManager(ManagerConfig{Store: store, AdminChecker: func() bool { return true }})
	ctx := context.Background()
	first := mgr.CheckStatus(ctx, addr)
	if first.FingerprintSHA256 == "" || first.FingerprintSHA256 == second.FingerprintSHA256 {
		t.Fatalf("initial status did not identify the first CA: %+v", first)
	}
	if _, err := mgr.InstallVerified(ctx, addr, first.FingerprintSHA256); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("InstallVerified with the replaced certificate = %v", err)
	}
	if _, _, count, _ := store.Inspect(""); count != 0 {
		t.Fatal("mismatched certificate was installed")
	}
	if _, err := mgr.InstallVerified(ctx, addr, "not-a-fingerprint"); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("InstallVerified with malformed fingerprint = %v", err)
	}
	result, err := mgr.InstallVerified(ctx, addr, strings.ToLower(second.FingerprintSHA256))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Installed || result.ActionScope != "LocalMachine" || result.FingerprintSHA256 != second.FingerprintSHA256 {
		t.Fatalf("InstallVerified reported a different certificate: %+v", result)
	}
	if requests.Load() != 3 {
		t.Fatalf("got %d certificate downloads, want 3", requests.Load())
	}
}

type unconfirmedTrustStore struct {
	*memCertStore
}

func (s unconfirmedTrustStore) Inspect(string) (bool, []string, int, error) {
	return false, nil, 0, errors.New("logical root unavailable")
}

func TestInstallVerifiedReportsUnconfirmedTrust(t *testing.T) {
	der := generateTestCertDER(t, "Current user Burp CA", true)
	ca, err := ParseAndValidateCA(der)
	if err != nil {
		t.Fatal(err)
	}
	burp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(der)
	}))
	defer burp.Close()
	store := newMemCertStore()
	mgr := NewManager(ManagerConfig{Store: unconfirmedTrustStore{store}})
	res, err := mgr.InstallVerified(context.Background(), burp.Listener.Addr().String(), ca.FingerprintSHA256)
	if !errors.Is(err, ErrTrustNotConfirmed) || res.Installed || res.ActionScope != "CurrentUser" {
		t.Fatalf("install = %+v, err = %v", res, err)
	}
	if res.StoreError != "logical root unavailable" || res.FingerprintSHA256 != ca.FingerprintSHA256 {
		t.Fatalf("unexpected trust verification details: %+v", res)
	}
	if found, _, _, _ := store.Inspect(ca.FingerprintSHA1); !found {
		t.Fatal("expected certificate to have been written before the logical store check failed")
	}
}

func TestUninstallPreservesPartialCleanupResult(t *testing.T) {
	der := generateTestCertDER(t, "Burp CA", true)
	burp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(der)
	}))
	defer burp.Close()
	store := newMemCertStore()
	_, _ = store.InstallRootCA(der, true)
	_, _ = store.InstallRootCA(der, false)
	mgr := NewManager(ManagerConfig{Store: store})
	res, err := mgr.Uninstall(context.Background(), burp.Listener.Addr().String())
	if !errors.Is(err, ErrCleanupIncomplete) || res.RemovedCount != 1 || res.Warning == "" || !res.Installed {
		t.Fatalf("cleanup = %+v, err = %v", res, err)
	}
}

func TestWindowsSystemStoreReadOnlyInspect(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific crypt32 store inspection test")
	}
	st := NewSystemStore()
	installed, scopes, _, err := st.Inspect("0000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("SystemStore.Inspect error: %v", err)
	}
	if installed || len(scopes) != 0 {
		t.Fatalf("unexpected match for dummy zero fingerprint: installed=%v scopes=%v", installed, scopes)
	}
}
