//go:build windows

package bridge

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

func TestParseTCPTable4AndTable6(t *testing.T) {
	// 构造 1 条 IPv4 记录：192.168.1.245:1433, State=5 (ESTABLISHED), PID=4242
	raw4 := make([]byte, 4+tcpRow4Size)
	binary.LittleEndian.PutUint32(raw4[0:4], 1)
	row4 := raw4[4:]
	binary.LittleEndian.PutUint32(row4[0:4], 5) // state
	copy(row4[12:16], net.IPv4(192, 168, 1, 245).To4())
	binary.BigEndian.PutUint16(row4[16:18], 1433)
	binary.LittleEndian.PutUint32(row4[20:24], 4242)

	got4 := parseTCPTable4(raw4)
	if len(got4) != 1 {
		t.Fatalf("len(got4) = %d, want 1", len(got4))
	}
	if got4[0].PID != 4242 || got4[0].State != 5 || got4[0].RemotePort != 1433 || got4[0].RemoteIP.String() != "192.168.1.245" {
		t.Fatalf("unexpected parsed v4 entry: %+v", got4[0])
	}

	// 构造 1 条 IPv6 记录：[2001:db8::9]:8443, State=5, PID=8484
	raw6 := make([]byte, 4+tcpRow6Size)
	binary.LittleEndian.PutUint32(raw6[0:4], 1)
	row6 := raw6[4:]
	copy(row6[24:40], net.ParseIP("2001:db8::9").To16())
	binary.BigEndian.PutUint16(row6[44:46], 8443)
	binary.LittleEndian.PutUint32(row6[48:52], 5)
	binary.LittleEndian.PutUint32(row6[52:56], 8484)

	got6 := parseTCPTable6(raw6)
	if len(got6) != 1 {
		t.Fatalf("len(got6) = %d, want 1", len(got6))
	}
	if got6[0].PID != 8484 || got6[0].State != 5 || got6[0].RemotePort != 8443 || got6[0].RemoteIP.String() != "2001:db8::9" {
		t.Fatalf("unexpected parsed v6 entry: %+v", got6[0])
	}

	// 真实调用 Windows iphlpapi.dll GetExtendedTcpTable，确认不崩溃且可解析
	live := collectActiveTCPConnections()
	for _, entry := range live {
		if entry.RemoteIP == nil {
			t.Fatalf("live TCP entry has nil RemoteIP: %+v", entry)
		}
	}
}

// 模拟高并发批量建连/断连抖动期间连续刷新 GetExtendedTcpTable 与进程列表，确认缓冲区重试稳定无报错。
func TestWindowsActiveTCPTableUnderBurstChurn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen churn server: %v", err)
	}
	defer ln.Close()

	var acceptWG sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			acceptWG.Add(1)
			go func(conn net.Conn) {
				defer acceptWG.Done()
				defer conn.Close()
				time.Sleep(15 * time.Millisecond)
			}(c)
		}
	}()

	stopChurn := make(chan struct{})
	var churnWG sync.WaitGroup
	// 并发批量建连/关连制造 TCP 表长度瞬时抖动
	for w := 0; w < 6; w++ {
		churnWG.Add(1)
		go func() {
			defer churnWG.Done()
			for {
				select {
				case <-stopChurn:
					return
				default:
					c, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
					if err == nil {
						time.Sleep(10 * time.Millisecond)
						_ = c.Close()
					}
				}
			}
		}()
	}

	// 并发高频刷新 GetExtendedTcpTable (IPv4/IPv6) 与完整进程详情列表
	errCh := make(chan error, 32)
	var pollWG sync.WaitGroup
	for r := 0; r < 4; r++ {
		pollWG.Add(1)
		go func() {
			defer pollWG.Done()
			for i := 0; i < 8; i++ {
				if _, err := getExtendedTCPTableRaw(afInet); err != nil {
					errCh <- err
					return
				}
				if items, err := ListRunningProcessDetails(context.Background()); err != nil {
					errCh <- err
					return
				} else if len(items) == 0 {
					errCh <- net.ErrClosed
					return
				} else {
					// 验证排序稳定性：活跃连接数严格非递增
					for j := 1; j < len(items); j++ {
						if items[j].ActiveConnections > items[j-1].ActiveConnections {
							t.Errorf("active_connections not sorted desc at index %d: %d > %d", j, items[j].ActiveConnections, items[j-1].ActiveConnections)
							return
						}
					}
				}
			}
		}()
	}

	pollWG.Wait()
	close(stopChurn)
	churnWG.Wait()
	_ = ln.Close()
	acceptWG.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("TCP table / process refresh failed under burst churn: %v", err)
	default:
	}
}
