package singbox

import (
	"context"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/accesslog"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

const maxAccessEvents = 100

var (
	// Wait before closing already-open extras so a node switch can drop the old IP.
	deviceOverflowHold = 60 * time.Second
	// Do not kick an IP that just appeared locally (user just landed on this node).
	deviceIPGrace = 45 * time.Second
)

// ipPool caches ipSnapshot maps to reduce allocations.
var ipPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]struct{}, 16)
	},
}

// ─── Per-user statistics ────────────────────────────────────────────────────

// userStats holds per-user traffic counters and alive IP tracking.
// Traffic counters are lock-free atomics (read on every packet).
// IP tracking uses a lightweight mutex (only touched at connect/disconnect).
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu        sync.RWMutex
	ips       map[string]int       // sourceIP → refcount
	ipFirst   map[string]time.Time // sourceIP → first local connect
	connCount int
}

func (u *userStats) addConn(sourceIP string) {
	sourceIP = normalizeDeviceIP(sourceIP)
	u.mu.Lock()
	u.connCount++
	if u.ips[sourceIP] == 0 {
		if u.ipFirst == nil {
			u.ipFirst = make(map[string]time.Time)
		}
		u.ipFirst[sourceIP] = time.Now()
	}
	u.ips[sourceIP]++
	u.mu.Unlock()
}

func (u *userStats) removeConn(sourceIP string) {
	sourceIP = normalizeDeviceIP(sourceIP)
	u.mu.Lock()
	u.connCount--
	u.ips[sourceIP]--
	if u.ips[sourceIP] <= 0 {
		delete(u.ips, sourceIP)
		delete(u.ipFirst, sourceIP)
	}
	u.mu.Unlock()
}

// distinctIPs returns the number of distinct IPs currently connected.
func (u *userStats) distinctIPs() int {
	u.mu.Lock()
	n := len(u.ips)
	u.mu.Unlock()
	return n
}

// ipSnapshot returns a pooled copy of the current IP set.
func (u *userStats) ipSnapshot() map[string]struct{} {
	cp := ipPool.Get().(map[string]struct{})
	for k := range cp {
		delete(cp, k)
	}
	u.mu.Lock()
	for ip := range u.ips {
		cp[ip] = struct{}{}
	}
	u.mu.Unlock()
	return cp
}

// releaseIPSnapshot returns the snapshot to pool.
// Large maps are discarded to prevent memory bloat.
func releaseIPSnapshot(m map[string]struct{}) {
	// Discard large maps to prevent pool memory bloat
	if len(m) > 64 {
		return
	}
	ipPool.Put(m)
}

// aliveIPList returns the set of alive IPs as a boolean map (for reporting).
func (u *userStats) aliveIPList() map[string]bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ips) == 0 {
		return nil
	}
	result := make(map[string]bool, len(u.ips))
	for ip := range u.ips {
		result[ip] = true
	}
	return result
}

// ─── ConnTracker ────────────────────────────────────────────────────────────

// ConnTracker provides per-user traffic counting, alive IP tracking, device
// limit gate-keeping, and per-user speed limiting for the sing-box kernel.
//
// Architecture: instead of maintaining a per-connection map (O(connections)),
// it maintains per-user atomic counters and IP refcount sets (O(users)).
// This means:
//   - GetUserTraffic is O(users), not O(connections)
//   - No Snapshot/pending buffer needed
//   - No per-connection map lock contention
//   - Bytes are counted directly into per-user atomics via CountFunc callbacks
//
// The per-connection wrapper (trackedConn) is still needed for:
//   - Hooking into sing's ReadCounter/WriteCounter for zero-copy byte counting
//   - Close callback to decrement IP refcounts
//   - Per-connection rate limit token accumulation (amortized WaitN)
type ConnTracker struct {
	usersMu   sync.RWMutex
	users     map[int]*userStats            // userID → stats
	uuidMap   map[string]int                // UUID → userID (for lookup in RoutedConnection)
	connMap   map[string]net.Conn           // connID → TCP conn (force-close)
	packetMap map[string]*trackedPacketConn // connID → UDP/QUIC conn (force-close)
	// blocked remembers UUIDs removed from the user table. Hysteria and TUIC
	// authenticate once per session, so a removed user can open another stream
	// on the old session until the UUID is rejected here.
	blocked map[string]int // UUID → userID

	idCounter atomic.Int64

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	speedLimitFunc atomic.Pointer[func(uuid string) *rate.Limiter]

	// deviceLimitFunc resolves a user UUID to their device limit.
	deviceLimitFunc atomic.Pointer[func(uuid string) (int, bool)]

	// Multi-node device state from panel
	globalDevices    map[int]map[string]bool // userID → IP → exists
	globalMu         sync.RWMutex
	globalLastUpdate time.Time

	overflowMu    sync.Mutex
	overflowSince map[int]time.Time

	accessMu  sync.Mutex
	access    map[string]*accesslog.Activity
	accessSeq atomic.Uint64
}

// NewConnTracker creates a tracker.
func NewConnTracker(_ int) *ConnTracker {
	return &ConnTracker{
		users:         make(map[int]*userStats),
		uuidMap:       make(map[string]int),
		connMap:       make(map[string]net.Conn),
		packetMap:     make(map[string]*trackedPacketConn),
		blocked:       make(map[string]int),
		globalDevices: make(map[int]map[string]bool),
		overflowSince: make(map[int]time.Time),
	}
}

// SetSpeedLimitFunc configures the per-user speed limit lookup.
func (t *ConnTracker) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	t.speedLimitFunc.Store(&fn)
}

// SetDeviceLimitFunc configures the per-user device limit lookup for gate-keeping.
func (t *ConnTracker) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	t.deviceLimitFunc.Store(&fn)
}

// SetUserMap replaces the UUID→userID mapping and ensures per-user stats
// structs exist for all users. Old users that are no longer present keep
// their stats until their connections drain.
func (t *ConnTracker) SetUserMap(m map[string]int) {
	if m == nil {
		m = map[string]int{}
	}
	t.usersMu.Lock()
	if t.blocked == nil {
		t.blocked = make(map[string]int)
	}
	for uuid, uid := range t.uuidMap {
		if _, ok := m[uuid]; !ok {
			t.blocked[uuid] = uid
		}
	}
	for uuid := range m {
		delete(t.blocked, uuid)
	}
	t.uuidMap = m
	for _, uid := range m {
		if _, ok := t.users[uid]; !ok {
			t.users[uid] = &userStats{ips: make(map[string]int), ipFirst: make(map[string]time.Time)}
		}
	}
	t.usersMu.Unlock()
}

func (t *ConnTracker) userBlocked(uuid string) bool {
	t.usersMu.RLock()
	_, ok := t.blocked[uuid]
	t.usersMu.RUnlock()
	return ok
}

// UpdateGlobalDevices syncs global device state from panel.
func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string) {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			if ip = normalizeDeviceIP(ip); ip != "" {
				m[ip] = true
			}
		}
		t.globalDevices[uid] = m
	}
	t.globalLastUpdate = time.Now()
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state updated", "users", len(users))
	if n := t.evictOverflowDevices(); n > 0 {
		nlog.Core().Info("evicted overflow device connections", "closed", n)
	}
}

// ClearGlobalDevices resets global device state (on WS disconnect).
func (t *ConnTracker) ClearGlobalDevices() {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool)
	t.globalLastUpdate = time.Time{}
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state cleared")
}

// ─── adapter.ConnectionTracker ──────────────────────────────────────────────

// RoutedConnection wraps a TCP conn to count bytes per-user, track IPs,
// and optionally rate-limit. Gate-keeps device limits at connection time.
func (t *ConnTracker) RoutedConnection(
	ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	uuid := metadata.User
	if t.userBlocked(uuid) {
		nlog.Core().Info("singbox: rejected connection for removed user", "user", uuid)
		conn.Close()
		return conn
	}
	sourceIP := normalizeDeviceIP(metadata.Source.Addr.String())
	destination := metadata.Destination.String()
	network := metadata.Network

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}

	activity := t.recordAccess(uid, sourceIP, network, destination)
	connID := t.nextID()
	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}
	wrapped := &trackedConn{
		Conn:     conn,
		tracker:  t,
		us:       us,
		userID:   uid,
		connID:   connID,
		sourceIP: sourceIP,
		limiter:  lim,
		ctx:      ctx,
		access:   activity,
	}
	t.usersMu.Lock()
	t.connMap[connID] = wrapped
	t.usersMu.Unlock()
	if us != nil {
		us.addConn(sourceIP)
		t.evictIfLocalOverflow(uuid, us)
	}
	return wrapped
}

// RoutedPacketConnection wraps UDP with per-user counting. Packet conns are
// stored separately from connMap so a removed user's QUIC/UDP sessions can be
// closed without touching anyone else.
func (t *ConnTracker) RoutedPacketConnection(
	ctx context.Context, conn N.PacketConn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	uuid := metadata.User
	if t.userBlocked(uuid) {
		nlog.Core().Info("singbox: rejected packet connection for removed user", "user", uuid)
		conn.Close()
		return conn
	}
	sourceIP := normalizeDeviceIP(metadata.Source.Addr.String())
	destination := metadata.Destination.String()
	network := metadata.Network

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()

	// Device limit gate-keeping
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if limit, hasLimit := (*dlf)(uuid); hasLimit {
			if t.checkDeviceGate(us, uid, sourceIP, limit) {
				nlog.Core().Info("singbox: device limit gate-keep, rejecting UDP connection",
					"user", uuid, "ip", sourceIP, "limit", limit)
				conn.Close()
				return conn
			}
		}
	}

	if us != nil {
		us.addConn(sourceIP)
		t.evictIfLocalOverflow(uuid, us)
	}
	activity := t.recordAccess(uid, sourceIP, network, destination)

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	wrapped := &trackedPacketConn{
		PacketConn: conn,
		tracker:    t,
		us:         us,
		userID:     uid,
		connID:     connID,
		sourceIP:   sourceIP,
		limiter:    lim,
		ctx:        ctx,
		access:     activity,
	}
	t.usersMu.Lock()
	t.packetMap[connID] = wrapped
	t.usersMu.Unlock()
	return wrapped
}

// RoutedFlow is required by official sing-box ConnectionTracker (TUN path).
// This node is a proxy inbound, not a TUN client, so there is nothing to wrap.
func (t *ConnTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

// checkDeviceGate rejects connections exceeding device limit.
// Dual-stack (one IPv4 + one IPv6) counts as one device: max(v4, v6).
func (t *ConnTracker) checkDeviceGate(us *userStats, userID int, sourceIP string, limit int) bool {
	if us == nil || limit <= 0 {
		return false
	}
	sourceIP = normalizeDeviceIP(sourceIP)

	us.mu.RLock()
	localIPs := make(map[string]bool, len(us.ips))
	for ip := range us.ips {
		localIPs[normalizeDeviceIP(ip)] = true
	}
	us.mu.RUnlock()

	if localIPs[sourceIP] {
		return false
	}

	t.globalMu.RLock()
	globalStale := time.Since(t.globalLastUpdate) > 60*time.Second
	globalIPs := t.globalDevices[userID]
	t.globalMu.RUnlock()

	allIPs := make(map[string]bool)
	for ip := range localIPs {
		allIPs[ip] = true
	}
	if !globalStale && globalIPs != nil {
		for ip := range globalIPs {
			allIPs[normalizeDeviceIP(ip)] = true
		}
		if globalIPs[sourceIP] {
			return false
		}
	}

	if effectiveDeviceCount(allIPs) < limit {
		return false
	}
	allIPs[sourceIP] = true
	if effectiveDeviceCount(allIPs) <= limit {
		return false
	}
	nlog.Core().Debug("device limit: rejecting extra device",
		"userID", userID, "ip", sourceIP, "limit", limit)
	return true
}

func (t *ConnTracker) evictIfLocalOverflow(uuid string, us *userStats) {
	dlf := t.deviceLimitFunc.Load()
	if dlf == nil || us == nil {
		return
	}
	limit, hasLimit := (*dlf)(uuid)
	if !hasLimit || limit <= 0 || us.distinctIPs() <= limit {
		return
	}
	if n := t.evictOverflowDevices(); n > 0 {
		nlog.Core().Info("evicted overflow device connections", "closed", n, "user", uuid)
	}
}

func (t *ConnTracker) mergedIPs(userID int, us *userStats) map[string]bool {
	all := make(map[string]bool)
	if us != nil {
		us.mu.RLock()
		for ip := range us.ips {
			all[normalizeDeviceIP(ip)] = true
		}
		us.mu.RUnlock()
	}
	t.globalMu.RLock()
	stale := time.Since(t.globalLastUpdate) > 60*time.Second
	if !stale {
		for ip := range t.globalDevices[userID] {
			all[normalizeDeviceIP(ip)] = true
		}
	}
	t.globalMu.RUnlock()
	return all
}

// extraLocalIPs are local addresses that push a family over `limit`.
// Young IPs (just switched nodes) are kept so a reconnect is not kicked.
func (t *ConnTracker) extraLocalIPs(userID int, us *userStats, limit int) map[string]bool {
	all := t.mergedIPs(userID, us)
	if effectiveDeviceCount(all) <= limit {
		t.overflowMu.Lock()
		delete(t.overflowSince, userID)
		t.overflowMu.Unlock()
		return nil
	}

	now := time.Now()
	t.overflowMu.Lock()
	since, ok := t.overflowSince[userID]
	if !ok {
		t.overflowSince[userID] = now
		since = now
	}
	held := now.Sub(since)
	t.overflowMu.Unlock()
	if deviceOverflowHold > 0 && held < deviceOverflowHold {
		return nil
	}

	byFamily := map[string][]string{"v4": {}, "v6": {}}
	for ip := range all {
		fam := ipFamily(ip)
		byFamily[fam] = append(byFamily[fam], ip)
	}
	extra := make(map[string]bool)
	for _, fam := range []string{"v4", "v6"} {
		list := byFamily[fam]
		if len(list) <= limit {
			continue
		}
		sort.Strings(list)
		for _, ip := range list[limit:] {
			extra[ip] = true
		}
	}
	if us == nil || len(extra) == 0 {
		return extra
	}
	us.mu.RLock()
	for ip, first := range us.ipFirst {
		ip = normalizeDeviceIP(ip)
		if extra[ip] && now.Sub(first) < deviceIPGrace {
			delete(extra, ip)
		}
	}
	us.mu.RUnlock()
	return extra
}

func (t *ConnTracker) evictOverflowDevices() int {
	dlf := t.deviceLimitFunc.Load()
	if dlf == nil {
		return 0
	}

	t.usersMu.RLock()
	uuidByID := make(map[int]string, len(t.uuidMap))
	for uuid, id := range t.uuidMap {
		uuidByID[id] = uuid
	}
	var toClose []net.Conn
	for uid, us := range t.users {
		uuid := uuidByID[uid]
		if uuid == "" {
			continue
		}
		limit, hasLimit := (*dlf)(uuid)
		if !hasLimit || limit <= 0 {
			continue
		}
		extra := t.extraLocalIPs(uid, us, limit)
		if len(extra) == 0 {
			continue
		}
		for _, conn := range t.connMap {
			tc, ok := conn.(*trackedConn)
			if !ok || tc.userID != uid {
				continue
			}
			if extra[normalizeDeviceIP(tc.sourceIP)] {
				toClose = append(toClose, conn)
			}
		}
	}
	t.usersMu.RUnlock()

	for _, conn := range toClose {
		_ = conn.Close()
	}
	return len(toClose)
}

func normalizeDeviceIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ip
	}
	if strings.HasPrefix(strings.ToLower(ip), "::ffff:") {
		ip = ip[7:]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func ipFamily(ip string) string {
	parsed := net.ParseIP(normalizeDeviceIP(ip))
	if parsed != nil && parsed.To4() == nil {
		return "v6"
	}
	return "v4"
}

func effectiveDeviceCount(ips map[string]bool) int {
	v4, v6 := 0, 0
	for ip := range ips {
		if ipFamily(ip) == "v6" {
			v6++
		} else {
			v4++
		}
	}
	if v4 > v6 {
		return v4
	}
	return v6
}

func (t *ConnTracker) nextID() string {
	return "sb-" + formatInt36(t.idCounter.Add(1))
}

func formatInt36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [13]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}

// ─── Public API ─────────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic and alive IPs.
// This is O(users), not O(connections).
func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	aliveIPs = make(map[int]map[string]bool, len(t.users))
	for uid, us := range t.users {
		up := us.upload.Load()
		down := us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}

		ips := us.aliveIPList()
		if ips != nil {
			aliveIPs[uid] = ips
		}

		us.mu.Lock()
		connCount += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return
}

func (t *ConnTracker) FlushRecentAccess() []accesslog.Event {
	t.accessMu.Lock()
	if len(t.access) == 0 {
		t.accessMu.Unlock()
		return nil
	}

	events := make([]accesslog.Event, 0, len(t.access))
	for id, activity := range t.access {
		if event, ok := activity.SnapshotIfChanged(); ok {
			events = append(events, event)
		}
		if activity.Closed() {
			delete(t.access, id)
		}
	}
	t.accessMu.Unlock()

	if len(events) == 0 {
		return nil
	}
	return events
}

func (t *ConnTracker) recordAccess(userID int, sourceIP, network, destination string) *accesslog.Activity {
	if userID <= 0 || destination == "" {
		return nil
	}
	seq := t.accessSeq.Add(1)
	sessionID := "singbox-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatUint(seq, 10)
	activity := accesslog.NewActivity(accesslog.Event{
		SessionID:   sessionID,
		UserID:      userID,
		XrayEmail:   "user@" + strconv.Itoa(userID),
		Source:      sourceIP,
		Network:     network,
		Destination: destination,
		Timestamp:   time.Now().Unix(),
	})

	t.accessMu.Lock()
	if t.access == nil {
		t.access = make(map[string]*accesslog.Activity)
	}
	if len(t.access) >= maxAccessEvents {
		for id, existing := range t.access {
			if existing.Closed() {
				delete(t.access, id)
				break
			}
		}
	}
	if len(t.access) >= maxAccessEvents {
		for id := range t.access {
			delete(t.access, id)
			break
		}
	}
	t.access[sessionID] = activity
	t.accessMu.Unlock()
	return activity
}

// CloseByID force-closes a connection by its ID.
func (t *ConnTracker) CloseByID(id string) bool {
	t.usersMu.RLock()
	conn, ok := t.connMap[id]
	t.usersMu.RUnlock()
	if !ok {
		return false
	}
	if conn != nil {
		conn.Close()
	}
	return true
}

// CloseByUUID force-closes TCP and UDP connections for one user UUID.
// A UUID that is no longer in the active map is still closed when it was
// removed and recorded in blocked. Missing UUIDs close nothing: user ID 0 is
// not a wildcard.
func (t *ConnTracker) CloseByUUID(uuid string) int {
	t.usersMu.Lock()
	uid, ok := t.uuidMap[uuid]
	if !ok {
		uid, ok = t.blocked[uuid]
	}
	if !ok {
		t.usersMu.Unlock()
		return 0
	}
	var conns []net.Conn
	for _, conn := range t.connMap {
		tc, isTracked := conn.(*trackedConn)
		if isTracked && tc.userID == uid {
			conns = append(conns, conn)
		}
	}
	var packets []*trackedPacketConn
	for _, pc := range t.packetMap {
		if pc != nil && pc.userID == uid {
			packets = append(packets, pc)
		}
	}
	t.usersMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	for _, pc := range packets {
		_ = pc.Close()
	}
	return len(conns) + len(packets)
}

// ActiveCount returns the total number of active connections.
func (t *ConnTracker) ActiveCount() int {
	t.usersMu.RLock()
	total := 0
	for _, us := range t.users {
		us.mu.Lock()
		total += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return total
}

// removeConnRef removes the connection reference from connMap on close.
func (t *ConnTracker) removeConnRef(connID string) {
	t.usersMu.Lock()
	delete(t.connMap, connID)
	delete(t.packetMap, connID)
	t.usersMu.Unlock()
}

// ─── trackedConn (TCP) ──────────────────────────────────────────────────────

// RateLimitedWriter wraps a Writer with non-blocking rate limiting.
// Uses AllowN for instant checks and context-aware waiting when needed.
type RateLimitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

// Write implements io.Writer with rate limiting.
func (w *RateLimitedWriter) Write(b []byte) (int, error) {
	// Truncate to burst size
	if burst := w.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	// Fast path: check if tokens available (non-blocking)
	if w.limiter.AllowN(time.Now(), len(b)) {
		return w.writer.Write(b)
	}

	// Slow path: wait for tokens with context cancellation support
	resv := w.limiter.ReserveN(time.Now(), len(b))
	if delay := resv.Delay(); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			// Tokens available, proceed
		case <-w.ctx.Done():
			resv.Cancel()
			return 0, w.ctx.Err()
		}
	}

	return w.writer.Write(b)
}

// RateLimitedReadCloser wraps a Reader with non-blocking rate limiting.
type RateLimitedReadCloser struct {
	reader  io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

// Read implements io.Reader with rate limiting.
func (r *RateLimitedReadCloser) Read(b []byte) (int, error) {
	// Truncate to burst size
	if burst := r.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	n, err := r.reader.Read(b)
	if n > 0 && r.limiter != nil {
		// Fast path: check if tokens available
		if !r.limiter.AllowN(time.Now(), n) {
			// Slow path: wait with context cancellation
			resv := r.limiter.ReserveN(time.Now(), n)
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-r.ctx.Done():
					resv.Cancel()
					return n, r.ctx.Err()
				}
			}
		}
	}
	return n, err
}

type trackedConn struct {
	net.Conn
	tracker  *ConnTracker
	us       *userStats // per-user stats (upload/download atomics + IP tracking)
	userID   int        // user ID for device tracking
	connID   string
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	access   *accesslog.Activity
	closed   atomic.Bool
}

func (c *trackedConn) Read(b []byte) (int, error) {
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		if c.us != nil {
			c.us.upload.Add(int64(n)) // 从入站读取 = 用户上传
		}
		c.access.AddUpload(int64(n))
		if c.limiter != nil {
			// Non-blocking rate limiting
			if !c.limiter.AllowN(time.Now(), n) {
				resv := c.limiter.ReserveN(time.Now(), n)
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return n, c.ctx.Err()
					}
				}
			}
		}
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	// Apply rate limiting before write
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
		// Non-blocking check first
		if !c.limiter.AllowN(time.Now(), len(b)) {
			resv := c.limiter.ReserveN(time.Now(), len(b))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return 0, c.ctx.Err()
				}
			}
		}
	}

	n, err := c.Conn.Write(b)
	if n > 0 && c.us != nil {
		c.us.download.Add(int64(n)) // 向入站写入 = 用户下载
	}
	if n > 0 {
		c.access.AddDownload(int64(n))
	}
	return n, err
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.access.Close()
		c.tracker.removeConnRef(c.connID)
	}
	return c.Conn.Close()
}

// makeCountFunc builds a CountFunc for zero-copy byte counting via sing's
// ReadCounter/WriteCounter unwrap interfaces.
func (c *trackedConn) makeCountFunc(counter *atomic.Int64, addAccess func(int64)) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) {
			counter.Add(n)
			if addAccess != nil {
				addAccess(n)
			}
		}
	}
	return func(n int64) {
		counter.Add(n)
		if addAccess != nil {
			addAccess(n)
		}
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.upload, c.access.AddUpload)} // 从入站读取 = 用户上传
}

func (c *trackedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.download, c.access.AddDownload)} // 向入站写入 = 用户下载
}

func (c *trackedConn) Upstream() any           { return c.Conn }
func (c *trackedConn) ReaderReplaceable() bool { return true }
func (c *trackedConn) WriterReplaceable() bool { return true }

// ─── trackedPacketConn (UDP / QUIC) ─────────────────────────────────────────

type trackedPacketConn struct {
	N.PacketConn
	tracker  *ConnTracker
	us       *userStats
	userID   int
	connID   string
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	access   *accesslog.Activity
	closed   atomic.Bool
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	dest, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := int64(buffer.Len())
		if c.us != nil {
			c.us.upload.Add(n) // 从入站读取 = 用户上传
		}
		c.access.AddUpload(n)
		if c.limiter != nil {
			// Non-blocking rate limiting with context cancellation
			if !c.limiter.AllowN(time.Now(), int(n)) {
				resv := c.limiter.ReserveN(time.Now(), int(n))
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return dest, c.ctx.Err()
					}
				}
			}
		}
	}
	return dest, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, dest singM.Socksaddr) error {
	n := int64(buffer.Len())

	// Apply rate limiting before write
	if c.limiter != nil {
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return c.ctx.Err()
				}
			}
		}
	}

	err := c.PacketConn.WritePacket(buffer, dest)
	if err == nil && c.us != nil {
		c.us.download.Add(n) // 向入站写入 = 用户下载
	}
	if err == nil {
		c.access.AddDownload(n)
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.access.Close()
		c.tracker.removeConnRef(c.connID)
	}
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) makeCountFunc(counter *atomic.Int64, addAccess func(int64)) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) {
			counter.Add(n)
			if addAccess != nil {
				addAccess(n)
			}
		}
	}
	return func(n int64) {
		counter.Add(n)
		if addAccess != nil {
			addAccess(n)
		}
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedPacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.download, c.access.AddDownload)}
}

func (c *trackedPacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.upload, c.access.AddUpload)}
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return true }
func (c *trackedPacketConn) WriterReplaceable() bool { return true }
