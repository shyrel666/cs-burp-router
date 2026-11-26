package detector

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// buildTestClientHello 构造标准二进制 TLS ClientHello 报文，支持自定义 legacyVersion、SNI 及 supported_versions 扩展。
func buildTestClientHello(recordVer, legacyVer uint16, sni string, supportedVersions []uint16) []byte {
	var body bytes.Buffer
	// client_version (2 bytes)
	_ = binary.Write(&body, binary.BigEndian, legacyVer)
	// random (32 bytes)
	body.Write(bytes.Repeat([]byte{0xab}, 32))
	// session_id length = 0
	body.WriteByte(0)
	// cipher_suites: 2 bytes len + 1 suite (TLS_AES_128_GCM_SHA256 = 0x1301)
	_ = binary.Write(&body, binary.BigEndian, uint16(2))
	_ = binary.Write(&body, binary.BigEndian, uint16(0x1301))
	// compression_methods: 1 byte len + null (0x00)
	body.Write([]byte{1, 0})

	var exts bytes.Buffer
	if sni != "" {
		// SNI extension (0x0000)
		var sniData bytes.Buffer
		nameBytes := []byte(sni)
		_ = binary.Write(&sniData, binary.BigEndian, uint16(len(nameBytes)+3))
		sniData.WriteByte(0x00) // host_name
		_ = binary.Write(&sniData, binary.BigEndian, uint16(len(nameBytes)))
		sniData.Write(nameBytes)

		_ = binary.Write(&exts, binary.BigEndian, uint16(0x0000))
		_ = binary.Write(&exts, binary.BigEndian, uint16(sniData.Len()))
		exts.Write(sniData.Bytes())
	}

	if len(supportedVersions) > 0 {
		// supported_versions extension (0x002b)
		var svData bytes.Buffer
		svData.WriteByte(byte(len(supportedVersions) * 2))
		for _, v := range supportedVersions {
			_ = binary.Write(&svData, binary.BigEndian, v)
		}
		_ = binary.Write(&exts, binary.BigEndian, uint16(0x002b))
		_ = binary.Write(&exts, binary.BigEndian, uint16(svData.Len()))
		exts.Write(svData.Bytes())
	}

	if exts.Len() > 0 {
		_ = binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
		exts.WriteTo(&body)
	}

	// Handshake header: 0x01 + 3-byte length
	hsLen := body.Len()
	var hs bytes.Buffer
	hs.WriteByte(0x01)
	hs.Write([]byte{byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)})
	hs.Write(body.Bytes())

	// TLS Record header: 0x16 + recordVer + 2-byte length
	var rec bytes.Buffer
	rec.WriteByte(0x16)
	_ = binary.Write(&rec, binary.BigEndian, recordVer)
	_ = binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func TestDetectTLSClientHelloTLS13WithSNIAndSplitPacket(t *testing.T) {
	det := NewDefault()
	client, server := newTCPPair(t)

	// 包含 GREASE (0x9a9a) + TLS 1.3 (0x0304) + TLS 1.2 (0x0303)，验证正确忽略 GREASE 并识别 TLS 1.3
	hello := buildTestClientHello(0x0301, 0x0303, "erp.internal.example", []uint16{0x9a9a, 0x0304, 0x0303})

	// 模拟 TCP 拆包：先发前 10 字节，15ms 后发剩余字节，验证 100ms 补读逻辑无丢字节
	go func() {
		_, _ = client.Write(hello[:10])
		time.Sleep(15 * time.Millisecond)
		_, _ = client.Write(hello[10:])
		_ = client.(*net.TCPConn).CloseWrite()
	}()

	res, err := det.Detect(server, 8443)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if res.Protocol != ProtoTLS {
		t.Fatalf("Protocol = %q, want %q", res.Protocol, ProtoTLS)
	}
	if res.SNI != "erp.internal.example" {
		t.Fatalf("SNI = %q, want %q", res.SNI, "erp.internal.example")
	}
	if res.TLSVersion != "TLS 1.3" {
		t.Fatalf("TLSVersion = %q, want %q", res.TLSVersion, "TLS 1.3")
	}
	if res.WeakTLS {
		t.Fatalf("WeakTLS = true for TLS 1.3, want false")
	}

	rest, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read remaining: %v", err)
	}
	reconstructed := append(append([]byte(nil), res.Buffered...), rest...)
	if !bytes.Equal(reconstructed, hello) {
		t.Fatalf("byte loss on split TLS 1.3 ClientHello: got %d bytes, want %d bytes", len(reconstructed), len(hello))
	}
}

func TestDetectTLSClientHelloRealStdlibTLS13(t *testing.T) {
	det := NewDefault()
	client, server := newTCPPair(t)

	// 使用 Go 标准库 crypto/tls 生成真实二进制 ClientHello
	go func() {
		tlsConn := tls.Client(client, &tls.Config{
			ServerName: "real-stdlib.corp.local",
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		})
		_ = tlsConn.SetDeadline(time.Now().Add(300 * time.Millisecond))
		_ = tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	res, err := det.Detect(server, 443)
	if err != nil {
		t.Fatalf("Detect real stdlib TLS error: %v", err)
	}
	if res.Protocol != ProtoTLS {
		t.Fatalf("Protocol = %q, want %q", res.Protocol, ProtoTLS)
	}
	if res.SNI != "real-stdlib.corp.local" {
		t.Fatalf("SNI = %q, want %q", res.SNI, "real-stdlib.corp.local")
	}
	if res.TLSVersion != "TLS 1.3" {
		t.Fatalf("TLSVersion = %q, want %q", res.TLSVersion, "TLS 1.3")
	}
	if res.WeakTLS {
		t.Fatalf("WeakTLS = true, want false")
	}
	if len(res.Buffered) < 50 {
		t.Fatalf("expected full buffered ClientHello, got only %d bytes", len(res.Buffered))
	}
}

func TestDetectTLSClientHelloWeakTLS10AndTLS11(t *testing.T) {
	det := NewDefault()

	cases := []struct {
		name        string
		hello       []byte
		wantSNI     string
		wantVersion string
		wantWeak    bool
	}{
		{
			name:        "TLS1.0_LegacyOnly",
			hello:       buildTestClientHello(0x0301, 0x0301, "legacy-oa.corp.local", nil),
			wantSNI:     "legacy-oa.corp.local",
			wantVersion: "TLS 1.0",
			wantWeak:    true,
		},
		{
			name:        "TLS1.1_SupportedVersions",
			hello:       buildTestClientHello(0x0301, 0x0302, "old-pay.corp.local", []uint16{0x0302, 0x0301}),
			wantSNI:     "old-pay.corp.local",
			wantVersion: "TLS 1.1",
			wantWeak:    true,
		},
		{
			name:        "TLS1.2_LegacyOnly",
			hello:       buildTestClientHello(0x0301, 0x0303, "modern.corp.local", nil),
			wantSNI:     "modern.corp.local",
			wantVersion: "TLS 1.2",
			wantWeak:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newTCPPair(t)
			if _, err := client.Write(tc.hello); err != nil {
				t.Fatalf("write hello: %v", err)
			}
			_ = client.(*net.TCPConn).CloseWrite()

			res, err := det.Detect(server, 443)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}
			if res.Protocol != ProtoTLS {
				t.Fatalf("Protocol = %q, want %q", res.Protocol, ProtoTLS)
			}
			if res.SNI != tc.wantSNI {
				t.Fatalf("SNI = %q, want %q", res.SNI, tc.wantSNI)
			}
			if res.TLSVersion != tc.wantVersion {
				t.Fatalf("TLSVersion = %q, want %q", res.TLSVersion, tc.wantVersion)
			}
			if res.WeakTLS != tc.wantWeak {
				t.Fatalf("WeakTLS = %v, want %v", res.WeakTLS, tc.wantWeak)
			}

			rest, _ := io.ReadAll(server)
			reconstructed := append(append([]byte(nil), res.Buffered...), rest...)
			if !bytes.Equal(reconstructed, tc.hello) {
				t.Fatalf("byte mismatch: got %d bytes, want %d bytes", len(reconstructed), len(tc.hello))
			}
		})
	}
}

func TestDetectMalformedAndTruncatedClientHelloZeroByteLoss(t *testing.T) {
	det := New(Config{
		PeekTimeout:    80 * time.Millisecond,
		TLSReadTimeout: 40 * time.Millisecond,
	})

	cases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "TruncatedHeaderOnly3Bytes",
			payload: []byte{0x16, 0x03, 0x01},
		},
		{
			name: "TruncatedMidBody",
			// 声明 Record 长度 200 字节，但实际仅发 18 字节后中断/静默
			payload: []byte{
				0x16, 0x03, 0x01, 0x00, 0xc8,
				0x01, 0x00, 0x00, 0xc4, 0x03, 0x03,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			},
		},
		{
			name: "MalformedExtensionLengthOverflow",
			payload: []byte{
				0x16, 0x03, 0x03, 0x00, 0x35,
				0x01, 0x00, 0x00, 0x31,
				0x03, 0x03,
				// 32 bytes random
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
				0x00,       // session_id len
				0x00, 0x02, // cipher suites len
				0x13, 0x01,
				0x01, 0x00, // compression
				0x00, 0x08, // extensions len
				0x00, 0x00, 0xff, 0xff, // malformed SNI extLen = 65535
				0xaa, 0xbb, 0xcc, 0xdd,
			},
		},
		{
			name: "OversizedRecordCappedAt4096ZeroLoss",
			payload: func() []byte {
				// 构造声明长度为 5000 字节的 TLS Record，验证不会超过 4096 限制且后续字节完整留在底层连接中无丢失
				buf := make([]byte, 5+5000)
				buf[0] = 0x16
				buf[1] = 0x03
				buf[2] = 0x03
				binary.BigEndian.PutUint16(buf[3:5], 5000)
				for i := 5; i < len(buf); i++ {
					buf[i] = byte(i & 0xff)
				}
				return buf
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newTCPPair(t)
			go func() {
				_, _ = client.Write(tc.payload)
				_ = client.(*net.TCPConn).CloseWrite()
			}()

			res, err := det.Detect(server, 8443)
			if err != nil {
				t.Fatalf("Detect must not error on malformed/truncated TLS: %v", err)
			}
			if res.Protocol != ProtoTLS {
				t.Fatalf("Protocol = %q, want %q", res.Protocol, ProtoTLS)
			}
			if len(res.Buffered) > MaxTLSRecordInspectSize && len(tc.payload) > MaxTLSRecordInspectSize {
				// bufio 初始单次读取上限为 4096，补读上限同样为 4096
				t.Fatalf("buffered %d exceeds MaxTLSRecordInspectSize %d", len(res.Buffered), MaxTLSRecordInspectSize)
			}

			rest, err := io.ReadAll(server)
			if err != nil {
				t.Fatalf("read remaining bytes: %v", err)
			}
			reconstructed := append(append([]byte(nil), res.Buffered...), rest...)
			if !bytes.Equal(reconstructed, tc.payload) {
				t.Fatalf("byte loss on %s: got %d bytes, want %d bytes", tc.name, len(reconstructed), len(tc.payload))
			}
		})
	}
}
