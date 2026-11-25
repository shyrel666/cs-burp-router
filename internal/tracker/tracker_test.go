package tracker

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTrackerRingBufferCapacityAndOrder(t *testing.T) {
	tr := New(5)
	if tr.Capacity() != 5 {
		t.Fatalf("got capacity %d, want 5", tr.Capacity())
	}

	var ids []uint64
	for i := 1; i <= 8; i++ {
		id := tr.Start(StartEntry{
			Target:   fmt.Sprintf("10.0.0.%d:80", i),
			Protocol: ProtoHTTP,
			Action:   ActionBurp,
		})
		ids = append(ids, id)
	}

	if tr.Len() != 5 {
		t.Fatalf("got len %d, want 5", tr.Len())
	}

	// 最新记录排在最前：应为 ID 8, 7, 6, 5, 4
	list := tr.List()
	wantIDs := []uint64{8, 7, 6, 5, 4}
	if len(list) != len(wantIDs) {
		t.Fatalf("got %d items, want %d", len(list), len(wantIDs))
	}
	for i, wantID := range wantIDs {
		if list[i].ID != wantID {
			t.Fatalf("list[%d].ID = %d, want %d", i, list[i].ID, wantID)
		}
		if list[i].Status != StatusActive {
			t.Fatalf("list[%d].Status = %q, want %q", i, list[i].Status, StatusActive)
		}
	}

	// 对已被环形缓冲淘汰的旧连接 ID (1) 调用 Finish，不得污染当前槽位上的新连接
	tr.Finish(ids[0], errors.New("stale connection error"))
	for _, rec := range tr.List() {
		if rec.Status != StatusActive || rec.Error != "" {
			t.Fatalf("evicted ID Finish corrupted active record %+v", rec)
		}
	}

	// 正常关闭 ID=8，报错关闭 ID=7
	tr.Finish(8, nil)
	tr.Finish(7, errors.New("burp connect refused"))

	updated := tr.List()
	if updated[0].ID != 8 || updated[0].Status != StatusClosed || updated[0].Error != "" {
		t.Fatalf("unexpected record 8 state: %+v", updated[0])
	}
	if updated[1].ID != 7 || updated[1].Status != StatusError || updated[1].Error != "burp connect refused" {
		t.Fatalf("unexpected record 7 state: %+v", updated[1])
	}
}

func TestTrackerClearAndMonotonicIDs(t *testing.T) {
	tr := New(DefaultCapacity)
	oldID := tr.Start(StartEntry{
		Target:   "127.0.0.1:3306",
		Protocol: ProtoFastPath,
		Action:   ActionDirect,
	})

	tr.Clear()
	if tr.Len() != 0 || len(tr.List()) != 0 {
		t.Fatalf("expected empty tracker after Clear, len=%d", tr.Len())
	}

	newID := tr.Start(StartEntry{
		Target:   "example.com:443",
		Protocol: ProtoTLS,
		Action:   ActionBurp,
	})
	if newID <= oldID {
		t.Fatalf("expected monotonic ID after Clear: newID=%d <= oldID=%d", newID, oldID)
	}

	// 清空前的活跃连接在之后才结束，不得影响新记录
	tr.Finish(oldID, errors.New("closed after clear"))
	recs := tr.List()
	if len(recs) != 1 || recs[0].ID != newID || recs[0].Status != StatusActive {
		t.Fatalf("oldID Finish affected post-clear records: %+v", recs)
	}
}

func TestTrackerSubscribeNotifications(t *testing.T) {
	tr := New(10)
	ch, unsub := tr.Subscribe()
	defer unsub()

	id := tr.Start(StartEntry{
		Target:   "api.local:8080",
		Protocol: ProtoHTTP,
		Action:   ActionBurp,
	})

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("did not receive Start notification")
	}

	tr.Finish(id, nil)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("did not receive Finish notification")
	}

	unsub()
	tr.Clear() // 取消订阅后不应阻塞或 panic
}

func TestTrackerConcurrentReadWriteRace(t *testing.T) {
	tr := New(50)
	var wg sync.WaitGroup

	// 并发写入与状态更新协程
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 120; i++ {
				id := tr.Start(StartEntry{
					ClientAddr: "127.0.0.1:50000",
					Target:     fmt.Sprintf("host-%d-%d.local:443", worker, i),
					Protocol:   ProtoTLS,
					Action:     ActionBurp,
				})
				if i%3 == 0 {
					tr.Finish(id, errors.New("mock err"))
				} else {
					tr.Finish(id, nil)
				}
			}
		}(w)
	}

	// 并发读取、订阅与清空协程
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func(reader int) {
			defer wg.Done()
			ch, unsub := tr.Subscribe()
			defer unsub()
			for i := 0; i < 80; i++ {
				_ = tr.Len()
				snapshot := tr.List()
				if len(snapshot) > 50 {
					t.Errorf("ring buffer exceeded capacity 50: got %d", len(snapshot))
				}
				if reader == 0 && i%25 == 0 {
					tr.Clear()
				}
				select {
				case <-ch:
				default:
				}
			}
		}(r)
	}

	wg.Wait()
	if tr.Len() > 50 {
		t.Fatalf("final Len %d exceeds capacity 50", tr.Len())
	}
}
