package xray

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/accesslog"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

const maxAccessEvents = 100

// Access xray's internal config creator registry so we can replace the
// default dispatcher factory with ours. This runs AFTER xray's init()
// functions because our package imports xray (dependency order guarantee).
//
//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

// globalLimitDispatcher is set when the factory creates a LimitDispatcher.
// The Xray kernel reads it to configure limits and get connections.
var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:      orig,
		innerDisp:  inner,
		limitedIPs: make(map[string]map[string]int),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

// LimitDispatcher wraps xray's DefaultDispatcher to enforce per-user
// admission checks before a request is dispatched into xray-core.
//
// It intentionally does NOT mutate transport.Link.Reader. Xray's mux/XUDP
// close path requires the original concrete *pipe.Reader to remain intact, so
// download-side per-connection byte accounting stays in xray-core stats while
// the dispatcher can safely wrap Writer for lifecycle and upload diagnostics.
type LimitDispatcher struct {
	inner     interface{}        // original DefaultDispatcher (Feature + Dispatcher)
	innerDisp routing.Dispatcher // same object, typed as Dispatcher

	// limitedUsers: users with device limit > 0, protected by mu.
	// Needs deterministic IP ordering for kick decisions.
	mu            sync.RWMutex
	limitedIPs    map[string]map[string]int // email → sourceIP → refcount
	deviceLimits  map[string]int            // email → max devices
	emailToUID    map[string]int            // email → panel user ID
	speedLimiters map[string]*rate.Limiter  // email → shared per-user limiter

	accessMu  sync.Mutex
	access    map[string]*accesslog.Activity
	accessSeq atomic.Uint64

	// userWriters keeps the links that can be interrupted for one user.
	// Removing a user closes only these, not the whole xray instance.
	userWriters map[string]map[*closeTrackingWriter]struct{}

	// unlimitedIPs: users without device limit — sync.Map for lock-free access.
	// Each entry is *ipCounter{ips sync.Map}.
	unlimitedIPs sync.Map // email → *ipCounter

	connCount atomic.Int64 // total active connections tracked by dispatcher
}

// ipCounter tracks IPs for unlimited users without any lock.
type ipCounter struct {
	ips sync.Map // sourceIP → *atomic.Int64 (refcount)
}

// aliveIPs returns a snapshot of distinct IPs.
func (ic *ipCounter) aliveIPs() map[string]bool {
	result := make(map[string]bool)
	ic.ips.Range(func(key, _ interface{}) bool {
		if rv, ok := ic.ips.Load(key); ok && rv.(*atomic.Int64).Load() > 0 {
			result[key.(string)] = true
		}
		return true
	})
	return result
}

// ─── routing.Dispatcher ──────────────────────────────────────────────────────

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	email, sourceIP, isTCP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return nil, err
	}

	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if email != "" && isTCP {
			d.delConn(email, sourceIP)
		}
		return nil, err
	}

	if email != "" {
		activity := d.recordAccess(email, sourceIP, dest)
		d.trackLink(ctx, link, email, sourceIP, isTCP, activity)
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	email, sourceIP, isTCP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return err
	}

	if email != "" {
		activity := d.recordAccess(email, sourceIP, dest)
		d.trackLink(ctx, link, email, sourceIP, isTCP, activity)
	}
	return d.innerDisp.DispatchLink(ctx, dest, link)
}

// identifyAndCheck extracts user identity from the session context, enforces
// device limits, and returns the user's email, source IP, and TCP flag.
// Returns a non-nil error only when the connection should be rejected.
func (d *LimitDispatcher) identifyAndCheck(ctx context.Context, dest net.Destination) (email, sourceIP string, isTCP bool, err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return "", "", false, nil
	}
	email = si.User.Email
	sourceIP = si.Source.Address.IP().String()
	isTCP = dest.Network == net.Network_TCP

	if d.checkDeviceLimit(email, sourceIP, isTCP) {
		nlog.Core().Debug("xray: device limit exceeded", "email", email, "ip", sourceIP)
		return "", "", false, errors.New("device limit exceeded for " + email)
	}
	return email, sourceIP, isTCP, nil
}

// trackLink records connection lifecycle without replacing link.Reader. This
// keeps mux/XUDP compatible while still allowing the dispatcher to release
// device-limit state when the link closes.
func (d *LimitDispatcher) trackLink(ctx context.Context, link *transport.Link, email, sourceIP string, isTCP bool, activity *accesslog.Activity) {
	d.connCount.Add(1)

	onClose := func() {
		if isTCP {
			d.delConn(email, sourceIP)
		}
		activity.Close()
		d.connCount.Add(-1)
	}

	d.mu.RLock()
	lim := d.speedLimiters[email]
	d.mu.RUnlock()

	w := &closeTrackingWriter{
		Writer:  link.Writer,
		access:  activity,
		limiter: lim,
		ctx:     ctx,
	}
	w.onClose = func() {
		d.unbindWriter(email, w)
		onClose()
	}
	d.bindWriter(email, w)
	link.Writer = w
}

func (d *LimitDispatcher) bindWriter(email string, w *closeTrackingWriter) {
	d.mu.Lock()
	if d.userWriters == nil {
		d.userWriters = make(map[string]map[*closeTrackingWriter]struct{})
	}
	set := d.userWriters[email]
	if set == nil {
		set = make(map[*closeTrackingWriter]struct{})
		d.userWriters[email] = set
	}
	set[w] = struct{}{}
	d.mu.Unlock()
}

func (d *LimitDispatcher) unbindWriter(email string, w *closeTrackingWriter) {
	d.mu.Lock()
	if set := d.userWriters[email]; set != nil {
		delete(set, w)
		if len(set) == 0 {
			delete(d.userWriters, email)
		}
	}
	d.mu.Unlock()
}

// CloseUser interrupts live links for one email. Other users stay up.
func (d *LimitDispatcher) CloseUser(email string) int {
	d.mu.Lock()
	set := d.userWriters[email]
	delete(d.userWriters, email)
	writers := make([]*closeTrackingWriter, 0, len(set))
	for w := range set {
		writers = append(writers, w)
	}
	d.mu.Unlock()
	for _, w := range writers {
		w.Interrupt()
	}
	return len(writers)
}

// ─── features.Feature (delegated) ───────────────────────────────────────────

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}

func (d *LimitDispatcher) Close() error {
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ─── Limit management (called by Xray kernel) ──────────────────────────────

func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits map[string]int, speedLimiters map[string]*rate.Limiter) {
	d.mu.Lock()
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.speedLimiters = speedLimiters
	d.mu.Unlock()
}

func (d *LimitDispatcher) ResetConns() {
	d.mu.Lock()
	d.limitedIPs = make(map[string]map[string]int)
	d.mu.Unlock()

	// Clear unlimited IPs
	d.unlimitedIPs.Range(func(key, _ interface{}) bool {
		d.unlimitedIPs.Delete(key)
		return true
	})

	d.connCount.Store(0)
}

func (d *LimitDispatcher) FlushRecentAccess() []accesslog.Event {
	d.accessMu.Lock()
	if len(d.access) == 0 {
		d.accessMu.Unlock()
		return nil
	}

	events := make([]accesslog.Event, 0, len(d.access))
	for id, activity := range d.access {
		if event, ok := activity.SnapshotIfChanged(); ok {
			events = append(events, event)
		}
		if activity.Closed() {
			delete(d.access, id)
		}
	}
	d.accessMu.Unlock()

	if len(events) == 0 {
		return nil
	}
	return events
}

func (d *LimitDispatcher) recordAccess(email, sourceIP string, dest net.Destination) *accesslog.Activity {
	d.mu.RLock()
	uid := d.emailToUID[email]
	d.mu.RUnlock()
	if uid <= 0 {
		return nil
	}

	seq := d.accessSeq.Add(1)
	sessionID := fmt.Sprintf("xray-%d-%d", time.Now().UnixNano(), seq)
	activity := accesslog.NewActivity(accesslog.Event{
		SessionID:   sessionID,
		UserID:      uid,
		XrayEmail:   email,
		Source:      sourceIP,
		Network:     dest.Network.SystemString(),
		Destination: dest.String(),
		Timestamp:   time.Now().Unix(),
	})

	d.accessMu.Lock()
	if d.access == nil {
		d.access = make(map[string]*accesslog.Activity)
	}
	if len(d.access) >= maxAccessEvents {
		for id, existing := range d.access {
			if existing.Closed() {
				delete(d.access, id)
				break
			}
		}
	}
	if len(d.access) >= maxAccessEvents {
		for id := range d.access {
			delete(d.access, id)
			break
		}
	}
	d.access[sessionID] = activity
	d.accessMu.Unlock()
	return activity
}

// GetConnectionState returns dispatcher-tracked alive IPs and connection count.
// Traffic bytes are intentionally left to xray's built-in stats pipeline.
func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	d.mu.RLock()
	emailToUID := d.emailToUID
	limitedIPs := d.limitedIPs
	d.mu.RUnlock()

	aliveIPs = make(map[int]map[string]bool)

	// Collect IPs from limited users (under RLock snapshot).
	for email, ipsMap := range limitedIPs {
		uid := emailToUID[email]
		if uid == 0 {
			continue
		}
		ipSet := make(map[string]bool, len(ipsMap))
		for ip := range ipsMap {
			ipSet[ip] = true
		}
		if len(ipSet) > 0 {
			aliveIPs[uid] = ipSet
		}
	}

	// Collect IPs from unlimited users (lock-free).
	d.unlimitedIPs.Range(func(key, value interface{}) bool {
		email := key.(string)
		uid := emailToUID[email]
		if uid == 0 {
			return true
		}
		ic := value.(*ipCounter)
		if ips := ic.aliveIPs(); len(ips) > 0 {
			// Merge with limited IPs if any
			if existing, ok := aliveIPs[uid]; ok {
				for ip := range ips {
					existing[ip] = true
				}
			} else {
				aliveIPs[uid] = ips
			}
		}
		return true
	})

	connCount = int(d.connCount.Load())
	return
}

// ─── Internal helpers ───────────────────────────────────────────────────────

// checkDeviceLimit enforces per-user device limits.
// Fast path: unlimited users use lock-free sync.Map.
// Slow path: limited users use RWMutex with deterministic IP ordering.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string, isTCP bool) bool {
	d.mu.RLock()
	limit, hasLimit := d.deviceLimits[email]
	d.mu.RUnlock()

	// Fast path: no device limit — use lock-free sync.Map.
	if !hasLimit || limit <= 0 {
		if isTCP {
			v, _ := d.unlimitedIPs.LoadOrStore(email, &ipCounter{})
			ic := v.(*ipCounter)

			// Increment IP refcount atomically.
			rv, _ := ic.ips.LoadOrStore(sourceIP, &atomic.Int64{})
			rv.(*atomic.Int64).Add(1)
		}
		return false
	}

	// Slow path: user has device limit — need deterministic ordering.
	d.mu.RLock()
	ips := d.limitedIPs[email]
	if ips != nil && ips[sourceIP] > 0 {
		d.mu.RUnlock()
		if isTCP {
			d.mu.Lock()
			d.limitedIPs[email][sourceIP]++
			d.mu.Unlock()
		}
		return false
	}

	if ips != nil && len(ips) < limit {
		d.mu.RUnlock()
		if isTCP {
			d.mu.Lock()
			if d.limitedIPs[email] == nil {
				d.limitedIPs[email] = make(map[string]int)
			}
			d.limitedIPs[email][sourceIP]++
			d.mu.Unlock()
		}
		return false
	}
	d.mu.RUnlock()

	// Over limit — need write lock for deterministic check.
	d.mu.Lock()
	defer d.mu.Unlock()

	// Re-check under write lock.
	ips = d.limitedIPs[email]
	if ips == nil {
		ips = make(map[string]int)
		d.limitedIPs[email] = ips
	}

	if ips[sourceIP] > 0 {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	if len(ips) < limit {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	// Over limit — deterministic: allow lowest IPs lexicographically.
	ipList := make([]string, 0, len(ips)+1)
	for ip := range ips {
		ipList = append(ipList, ip)
	}
	ipList = append(ipList, sourceIP)
	sort.Strings(ipList)

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i] == sourceIP {
			if isTCP {
				ips[sourceIP]++
			}
			return false
		}
	}
	return true
}

// delConn decrements the IP refcount when a connection closes.
func (d *LimitDispatcher) delConn(email, sourceIP string) {
	// Check if this is an unlimited user first (lock-free).
	if v, ok := d.unlimitedIPs.Load(email); ok {
		ic := v.(*ipCounter)
		if rv, ok := ic.ips.Load(sourceIP); ok {
			counter := rv.(*atomic.Int64)
			if counter.Add(-1) <= 0 {
				ic.ips.Delete(sourceIP)
			}
		}
		return
	}

	// Limited user — use write lock.
	d.mu.Lock()
	defer d.mu.Unlock()
	if ips, ok := d.limitedIPs[email]; ok {
		ips[sourceIP]--
		if ips[sourceIP] <= 0 {
			delete(ips, sourceIP)
		}
		if len(ips) == 0 {
			delete(d.limitedIPs, email)
		}
	}
}

type closeTrackingWriter struct {
	buf.Writer
	onClose func()
	access  *accesslog.Activity
	limiter *rate.Limiter
	ctx     context.Context
	closed  atomic.Bool
}

func (w *closeTrackingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.limiter != nil {
		ctx := w.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if err := waitRateLimit(ctx, w.limiter, int(mb.Len())); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	n := int64(mb.Len())
	err := w.Writer.WriteMultiBuffer(mb)
	if err == nil {
		w.access.AddUpload(n)
	}
	return err
}

func waitRateLimit(ctx context.Context, lim *rate.Limiter, n int) error {
	if n <= 0 {
		return nil
	}
	burst := lim.Burst()
	if burst <= 0 {
		burst = 1
	}
	for n > 0 {
		chunk := n
		if chunk > burst {
			chunk = burst
		}
		if err := lim.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

func (w *closeTrackingWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	return common.Close(w.Writer)
}

func (w *closeTrackingWriter) Interrupt() {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	common.Interrupt(w.Writer)
}
