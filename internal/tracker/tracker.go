package tracker

import (
	"sync"
	"time"
)

const (
	// DefaultCapacity 是内存环形缓冲默认保留的最大连接记录条数。
	DefaultCapacity = 200
)

// 识别协议常量（用于看板展示与记录归类）。
const (
	ProtoHTTP     = "HTTP"
	ProtoTLS      = "TLS/HTTPS"
	ProtoUnknown  = "TCP/Unknown"
	ProtoFastPath = "FastPath"
	ProtoLoopback = "Loopback"
)

// 路由动作常量。
const (
	ActionBurp     = "Burp"
	ActionDirect   = "Direct"
	ActionRejected = "Rejected"
)

// 连接生命周期状态常量。
const (
	StatusActive = "Active"
	StatusClosed = "Closed"
	StatusError  = "Error"
)

// Record 表示单条连接的完整追踪快照。
type Record struct {
	ID         uint64    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	ClientAddr string    `json:"clientAddr,omitempty"`
	Target     string    `json:"target"`
	Protocol   string    `json:"protocol"`
	Action     string    `json:"action"`
	Status     string    `json:"status"`
	Error      string    `json:"error"`
}

// StartEntry 定义新连接进入路由阶段时写入追踪器的初始字段。
type StartEntry struct {
	Timestamp  time.Time
	ClientAddr string
	Target     string
	Protocol   string
	Action     string
}

// Tracker 维护固定容量的并发安全连接环形缓冲区，并支持实时变更订阅。
type Tracker struct {
	mu       sync.RWMutex
	capacity int
	buf      []Record
	head     int
	count    int
	nextID   uint64
	byID     map[uint64]int

	subMu sync.Mutex
	subs  map[chan struct{}]struct{}
}

// New 创建指定容量的连接追踪器；capacity <= 0 时使用 DefaultCapacity (200)。
func New(capacity int) *Tracker {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Tracker{
		capacity: capacity,
		buf:      make([]Record, capacity),
		byID:     make(map[uint64]int, capacity),
		subs:     make(map[chan struct{}]struct{}),
	}
}

// Capacity 返回环形缓冲区的最大容量。
func (t *Tracker) Capacity() int {
	return t.capacity
}

// Len 返回当前已缓存的连接记录条数。
func (t *Tracker) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count
}

// Start 记录一条新连接（初始状态为 Active），返回唯一递增记录 ID。
func (t *Tracker) Start(entry StartEntry) uint64 {
	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	t.mu.Lock()
	t.nextID++
	id := t.nextID

	if t.count == t.capacity {
		evictedID := t.buf[t.head].ID
		delete(t.byID, evictedID)
	} else {
		t.count++
	}

	t.buf[t.head] = Record{
		ID:         id,
		Timestamp:  ts,
		ClientAddr: entry.ClientAddr,
		Target:     entry.Target,
		Protocol:   entry.Protocol,
		Action:     entry.Action,
		Status:     StatusActive,
		Error:      "",
	}
	t.byID[id] = t.head
	t.head = (t.head + 1) % t.capacity
	t.mu.Unlock()

	t.notify()
	return id
}

// Finish 在连接结束时更新对应记录的最终状态（err == nil 为 Closed，否则为 Error 并记录错误信息）。
// 若该记录已被环形缓冲区淘汰或已被清空，则安全忽略。
func (t *Tracker) Finish(id uint64, err error) {
	if id == 0 {
		return
	}

	updated := false
	t.mu.Lock()
	if idx, ok := t.byID[id]; ok && t.buf[idx].ID == id {
		if err != nil {
			t.buf[idx].Status = StatusError
			t.buf[idx].Error = err.Error()
		} else {
			t.buf[idx].Status = StatusClosed
			t.buf[idx].Error = ""
		}
		updated = true
	}
	t.mu.Unlock()

	if updated {
		t.notify()
	}
}

// List 按时间倒序（最新连接在前）返回当前所有连接记录的深拷贝切片。
func (t *Tracker) List() []Record {
	t.mu.RLock()
	out := make([]Record, t.count)
	for i := 0; i < t.count; i++ {
		idx := (t.head - 1 - i + 2*t.capacity) % t.capacity
		out[i] = t.buf[idx]
	}
	t.mu.RUnlock()
	return out
}

// Clear 清空当前所有缓存的连接记录（保留单调递增的 nextID 防止旧连接关闭时误改新记录）。
func (t *Tracker) Clear() {
	t.mu.Lock()
	clear(t.buf)
	clear(t.byID)
	t.head = 0
	t.count = 0
	t.mu.Unlock()

	t.notify()
}

// Subscribe 注册一个非阻塞变更通知通道，供 SSE 实时流监听；调用返回的取消函数即可解除订阅。
func (t *Tracker) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	t.subMu.Lock()
	t.subs[ch] = struct{}{}
	t.subMu.Unlock()

	unsubscribe := func() {
		t.subMu.Lock()
		delete(t.subs, ch)
		t.subMu.Unlock()
	}
	return ch, unsubscribe
}

func (t *Tracker) notify() {
	t.subMu.Lock()
	for ch := range t.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	t.subMu.Unlock()
}
