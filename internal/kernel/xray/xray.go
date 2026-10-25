package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	xrayProxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"golang.org/x/time/rate"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/cedar2025/xboard-node/internal/accesslog"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/geodata"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

const (
	// drainTimeout is how long Stop waits for in-flight connections to finish
	// before hard-killing the instance. Skipped during hot-reload for speed.
	drainTimeout = 5 * time.Second
	// startTimeout caps how long instance.Start() may block.
	startTimeout = 30 * time.Second
)

// Xray implements kernel.Kernel by embedding xray-core as a Go library.
//
// Lifecycle:  Start  →  running  →  Stop / Reload
//
// Lock discipline:
//   - mu is held only for brief field swaps (microseconds).
//   - instance.Start() and instance.Close() run OUTSIDE the lock.
//   - running (atomic) gates fast-path checks in IsRunning / GetConnections.
type Xray struct {
	cfg config.KernelConfig

	// mu protects instance, limitDispatcher, users, protocol, inboundTag,
	// lastKernelHash, and cumTraffic. Never held during slow I/O.
	mu              sync.Mutex
	instance        *xrayCore.Instance
	limitDispatcher *LimitDispatcher
	users           []model.UserSpec
	nodeConfig      *model.NodeSpec
	tls             kernel.TLSCert
	protocol        string
	inboundTag      string
	lastKernelHash  string
	cumTraffic      map[int][2]int64
	speedLimitFunc  func(string) *rate.Limiter
	// removedEmail keeps UUID → email after a user leaves the active table,
	// so a later close can still find the links that were tracked by email.
	removedEmail map[string]string

	// running is set after a successful Start and cleared before shutdown.
	// Atomic so IsRunning / GetConnections never block.
	running atomic.Bool
}

func New(cfg config.KernelConfig) *Xray {
	return &Xray{
		cfg:        cfg,
		cumTraffic: make(map[int][2]int64),
	}
}

func (x *Xray) Name() string { return "xray" }

func (x *Xray) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  true,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       false,
	}
}

func (x *Xray) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria",
	}
}

// ─── Lifecycle ──────────────────────────────────────────────────────────────

// Start builds a new xray-core instance and atomically replaces the old
// one. The method is organised in five non-overlapping phases so that the
// kernel mutex is never held during slow operations (Start / Close).
// Crucially, the old instance stays alive until the new one is confirmed
// running — if StartNew fails, the old instance is untouched.
//
//	Phase 1 – Build:      generate protobuf config  (no lock, pure computation)
//	Phase 2 – Create:     xrayCore.New + capture LD (brief global lock)
//	Phase 3 – StartNew:   instance.Start            (no lock, potentially slow)
//	Phase 4 – Swap:       store new, extract old     (brief kernel lock)
//	Phase 5 – RecycleOld: close old in background    (non-blocking)
func (x *Xray) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	// ── Phase 1: Build config (no shared state) ─────────────────────────
	x.ensureGeoData(nodeConfig)

	data, err := marshalConfig(x.cfg, nodeConfig, users, tls)
	if err != nil {
		return err
	}

	pbConfig, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parse xray config: %w", err)
	}

	// ── Phase 2: Create instance (global lock for LD capture) ───────────
	xrayCreationMu.Lock()
	inst, err := xrayCore.New(pbConfig)
	ld := globalLimitDispatcher.Load()
	xrayCreationMu.Unlock()
	if err != nil {
		return fmt.Errorf("create xray: %w", err)
	}

	// ── Phase 3: Start new (no lock, potentially slow) ──────────────────
	if err := startWithTimeout(inst, startTimeout); err != nil {
		inst.Close()
		return err
	}

	// ── Phase 4: Swap old → new (brief kernel lock) ─────────────────────
	x.mu.Lock()
	old := x.instance
	oldLD := x.limitDispatcher
	x.instance = inst
	x.limitDispatcher = ld
	x.users = users
	x.removedEmail = nil
	x.nodeConfig = nodeConfig
	x.tls = tls
	x.protocol = nodeConfig.Protocol
	x.inboundTag = nodeConfig.Protocol + "-in"
	x.cumTraffic = make(map[int][2]int64)
	x.lastKernelHash = kernel.ComputeHash(nodeConfig, users)
	x.running.Store(true)
	x.mu.Unlock()

	// ── Phase 5: Recycle old (background, non-blocking) ─────────────────
	closeOld(old, oldLD)

	x.updateDispatcherLimits(users)

	nlog.Core().Info("xray started",
		"users", len(users),
		"protocol", nodeConfig.Protocol,
	)
	return nil
}

// Reload updates dispatcher limits and handles configuration changes.
// Since Xray does not support granular inbound reconstruction without an
// instance restart for most transport/TLS settings, it triggers a full restart
// if any kernel-affecting fields (hash mismatch) have changed.
func (x *Xray) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	x.updateDispatcherLimits(users)

	newHash := kernel.ComputeHash(nodeConfig, users)

	x.mu.Lock()
	same := x.lastKernelHash == newHash && tlsEqual(x.tls, tls)
	if same {
		x.users = users
		x.mu.Unlock()
		nlog.Core().Debug("xray: limits updated, kernel configuration unchanged")
		return nil
	}
	x.mu.Unlock()

	nlog.Core().Info("xray: configuration changed, performing full restart")
	return x.Start(nodeConfig, users, tls)
}

// Stop gracefully shuts down the kernel, draining active connections first.
func (x *Xray) Stop() {
	x.running.Store(false)

	x.mu.Lock()
	inst := x.instance
	ld := x.limitDispatcher
	x.instance = nil
	x.limitDispatcher = nil
	x.mu.Unlock()

	if ld != nil {
		drainConns(ld, drainTimeout)
	}
	closeOld(inst, ld)
}

func (x *Xray) IsRunning() bool { return x.running.Load() }

func tlsEqual(a, b kernel.TLSCert) bool {
	return bytes.Equal(a.CertPEM, b.CertPEM) && bytes.Equal(a.KeyPEM, b.KeyPEM)
}

// ─── Observability ──────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic from xray's built-in
// stats pipeline and connection state from the admission dispatcher when
// available. The dispatcher intentionally no longer wraps transport links,
// so traffic accounting must come from xray-core itself.
func (x *Xray) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	if !x.running.Load() {
		return nil, nil, 0, nil
	}

	x.mu.Lock()
	ld := x.limitDispatcher
	traffic, err = x.aggregateStats()
	x.mu.Unlock()
	if err != nil {
		return nil, nil, 0, err
	}

	if ld != nil {
		aliveIPs, connCount = ld.GetConnectionState()
	}
	return traffic, aliveIPs, connCount, nil
}

func (x *Xray) FlushRecentAccess() []accesslog.Event {
	x.mu.Lock()
	ld := x.limitDispatcher
	x.mu.Unlock()
	if ld == nil {
		return nil
	}
	return ld.FlushRecentAccess()
}

func (x *Xray) CloseConnection(_ context.Context, _ string) error {
	// No-op: xray doesn't support force-closing individual connections.
	// User removal goes through RemoveUsers which removes the inbound user.
	return nil
}

func (x *Xray) CloseUserConnections(_ context.Context, uuid string) error {
	x.mu.Lock()
	ld := x.limitDispatcher
	email := ""
	for _, u := range x.users {
		if u.UUID == uuid {
			email = userEmail(u.ID)
			break
		}
	}
	if email == "" && x.removedEmail != nil {
		email = x.removedEmail[uuid]
	}
	x.mu.Unlock()
	if ld == nil || email == "" {
		return nil
	}
	ld.CloseUser(email)
	return nil
}

// SetSpeedLimitFunc stores the shared per-user limiter callback and refreshes
// dispatcher speed limits. New connections pick up the limiter via Writer wrap.
func (x *Xray) SetSpeedLimitFunc(fn func(string) *rate.Limiter) {
	x.mu.Lock()
	x.speedLimitFunc = fn
	users := x.users
	x.mu.Unlock()
	x.updateDispatcherLimits(users)
}

// SetDeviceLimitFunc is a no-op for xray — device limits are already
// gate-kept by LimitDispatcher.checkDeviceLimit at Dispatch time.
func (x *Xray) SetDeviceLimitFunc(_ func(string) (int, bool)) {}

// UpdateGlobalDevices is a no-op for xray — xray handles device limits differently.
func (x *Xray) UpdateGlobalDevices(_ map[int][]string) {}

// ClearGlobalDevices is a no-op for xray.
func (x *Xray) ClearGlobalDevices() {}

// ─── User management (non-disruptive where possible) ────────────────────────

// AddUsers merges new users into the running Xray instance.
// Credential changes patch the inbound UserManager and close only the users
// whose UUID changed. A full instance restart is the fallback when the
// protocol has no UserManager.
func (x *Xray) AddUsers(users []model.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}

	// Merge: overwrite existing users' properties, collect truly new ones.
	userMap := make(map[int]model.UserSpec, len(x.users))
	for _, u := range x.users {
		userMap[u.ID] = u
	}
	var toAdd []model.UserSpec
	for _, u := range users {
		if _, exists := userMap[u.ID]; exists {
			userMap[u.ID] = u // property update for an existing kernel user
		} else {
			toAdd = append(toAdd, u)
			userMap[u.ID] = u
		}
	}

	if len(toAdd) == 0 {
		// No new kernel users, but properties (limits) may have changed.
		merged := usersFromMap(userMap)
		x.users = merged
		x.mu.Unlock()
		x.updateDispatcherLimits(merged)
		return 0, nil
	}

	targetUsers := usersFromMap(userMap)
	x.mu.Unlock()

	if err := x.syncUserTable(targetUsers); err != nil {
		return 0, err
	}
	nlog.Core().Info("xray: users added", "added", len(toAdd), "total", len(targetUsers))
	return len(toAdd), nil
}

// RemoveUsers removes users from the running Xray instance and closes their
// live links. Other users stay connected. The instance stops only when the
// last user is removed.
func (x *Xray) RemoveUsers(users []model.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}
	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []model.UserSpec
	var gone []model.UserSpec
	for _, u := range x.users {
		if _, rm := removeSet[u.ID]; rm {
			gone = append(gone, u)
		} else {
			kept = append(kept, u)
		}
	}
	if len(gone) == 0 {
		x.mu.Unlock()
		return 0, nil
	}

	if len(kept) == 0 {
		ld := x.limitDispatcher
		emails := make([]string, 0, len(gone))
		for _, u := range gone {
			x.noteRemovedLocked(u)
			emails = append(emails, userEmail(u.ID))
		}
		x.mu.Unlock()
		if ld != nil {
			for _, email := range emails {
				ld.CloseUser(email)
			}
		}
		x.Stop()
		return len(gone), nil
	}
	x.mu.Unlock()

	if err := x.syncUserTable(kept); err != nil {
		return 0, err
	}
	nlog.Core().Info("xray: users removed", "removed", len(gone), "total", len(kept))
	return len(gone), nil
}

// UpdateUsers replaces the entire user set. Limit-only changes update the
// dispatcher. Membership changes patch UserManager and close removed users.
func (x *Xray) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, 0, fmt.Errorf("not running")
	}
	toAdd, toRemove := kernel.UserDiff(x.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		// Only limits changed — update dispatcher without restart.
		x.users = users
		x.mu.Unlock()
		x.updateDispatcherLimits(users)
		nlog.Core().Info("xray: limits updated, kernel unchanged")
		return 0, 0, nil
	}
	x.mu.Unlock()

	if err = x.syncUserTable(users); err != nil {
		return 0, 0, err
	}
	nlog.Core().Info("xray: users updated", "added", added, "removed", removed, "total", len(users))
	return
}

// syncUserTable applies a credential diff through the inbound UserManager and
// interrupts links that belong to removed users. It restarts the instance
// only when the protocol cannot patch users in place.
func (x *Xray) syncUserTable(target []model.UserSpec) error {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return fmt.Errorf("not running")
	}
	toAdd, toRemove := kernel.UserDiff(x.users, target)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		x.users = append([]model.UserSpec(nil), target...)
		x.mu.Unlock()
		x.updateDispatcherLimits(target)
		return nil
	}

	um, err := x.getUserManager()
	if err != nil {
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Warn("xray: user table patch unavailable, restarting instance", "error", err)
		return x.Start(nc, target, t)
	}

	emails := make([]string, 0, len(toRemove))
	for _, u := range toRemove {
		if err := um.RemoveUser(context.Background(), userEmail(u.ID)); err != nil {
			nc, t := x.nodeConfig, x.tls
			x.mu.Unlock()
			nlog.Core().Warn("xray: RemoveUser failed, restarting instance", "id", u.ID, "error", err)
			return x.Start(nc, target, t)
		}
		x.noteRemovedLocked(u)
		emails = append(emails, userEmail(u.ID))
	}
	for _, u := range toAdd {
		mem, err := toMemoryUser(x.protocol, x.nodeConfig, u)
		if err != nil {
			nc, t := x.nodeConfig, x.tls
			x.mu.Unlock()
			nlog.Core().Warn("xray: build user failed, restarting instance", "id", u.ID, "error", err)
			return x.Start(nc, target, t)
		}
		if err := um.AddUser(context.Background(), mem); err != nil {
			nc, t := x.nodeConfig, x.tls
			x.mu.Unlock()
			nlog.Core().Warn("xray: AddUser failed, restarting instance", "id", u.ID, "error", err)
			return x.Start(nc, target, t)
		}
		delete(x.removedEmail, u.UUID)
	}
	x.users = append([]model.UserSpec(nil), target...)
	ld := x.limitDispatcher
	x.mu.Unlock()

	x.updateDispatcherLimits(target)
	if ld != nil {
		for _, email := range emails {
			ld.CloseUser(email)
		}
	}
	return nil
}

func (x *Xray) noteRemovedLocked(u model.UserSpec) {
	if u.UUID == "" {
		return
	}
	if x.removedEmail == nil {
		x.removedEmail = make(map[string]string)
	}
	x.removedEmail[u.UUID] = userEmail(u.ID)
}

var _ kernel.Kernel = (*Xray)(nil)

// ─── Internal helpers ───────────────────────────────────────────────────────

// getUserManager extracts the UserManager from the running xray instance's
// inbound handler. Must be called with x.mu held.
// Returns error for protocols that don't support UserManager (socks, http).
func (x *Xray) getUserManager() (xrayProxy.UserManager, error) {
	if x.instance == nil {
		return nil, fmt.Errorf("instance is nil")
	}

	im := x.instance.GetFeature(inbound.ManagerType())
	if im == nil {
		return nil, fmt.Errorf("inbound manager not available")
	}
	inboundMgr, ok := im.(inbound.Manager)
	if !ok {
		return nil, fmt.Errorf("inbound manager type assertion failed")
	}

	handler, err := inboundMgr.GetHandler(context.Background(), x.inboundTag)
	if err != nil {
		return nil, fmt.Errorf("get handler %q: %w", x.inboundTag, err)
	}

	gi, ok := handler.(xrayProxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler does not implement GetInbound")
	}

	um, ok := gi.GetInbound().(xrayProxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("protocol %q does not support UserManager", x.protocol)
	}

	return um, nil
}

// toMemoryUser converts a model.UserSpec into an xray protocol.MemoryUser for the
// given protocol. Each protocol needs a different Account type.
func toMemoryUser(proto string, nc *model.NodeSpec, u model.UserSpec) (*protocol.MemoryUser, error) {
	email := userEmail(u.ID)
	mu := &protocol.MemoryUser{Email: email, Level: 0}

	switch proto {
	case "vmess":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vmess UUID: %w", err)
		}
		mu.Account = &vmess.MemoryAccount{
			ID:       protocol.NewID(id),
			Security: protocol.SecurityType_AUTO,
		}

	case "vless":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vless UUID: %w", err)
		}
		account := &vless.MemoryAccount{
			ID:         protocol.NewID(id),
			Encryption: "none",
		}
		if nc.Flow != "" {
			account.Flow = nc.Flow
		}
		mu.Account = account

	case "trojan":
		mu.Account = &trojan.MemoryAccount{
			Password: u.UUID,
			Key:      trojanHexSha224(u.UUID),
		}

	case "shadowsocks":
		if strings.HasPrefix(nc.Cipher, "2022-blake3-") {
			// 2022-blake3 multi-user mode. Xray stores the key as raw bytes and
			// accepts either standard base64 or the original string.
			mu.Account = &ss2022.MemoryAccount{Key: ss2022Key(u.UUID)}
		} else {
			// Traditional SS — build via getCipher path
			ct := parseCipherType(nc.Cipher)
			cipherObj, err := (&shadowsocks.Account{CipherType: ct, Password: u.UUID}).AsAccount()
			if err != nil {
				return nil, fmt.Errorf("build ss account: %w", err)
			}
			mu.Account = cipherObj
		}

	default:
		return nil, fmt.Errorf("protocol %q does not support MemoryUser", proto)
	}

	return mu, nil
}

func ss2022Key(key string) []byte {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return []byte(key)
	}
	return raw
}

func usersFromMap(userMap map[int]model.UserSpec) []model.UserSpec {
	users := make([]model.UserSpec, 0, len(userMap))
	for _, user := range userMap {
		users = append(users, user)
	}
	return users
}

// parseCipherType maps a cipher name string to the xray CipherType enum.
func parseCipherType(cipher string) shadowsocks.CipherType {
	switch cipher {
	case "aes-128-gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-ietf-poly1305", "xchacha20-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		// Official Xray v26 dropped CipherType_NONE; unknown ciphers are rejected.
		return shadowsocks.CipherType_UNKNOWN
	default:
		return shadowsocks.CipherType_AES_256_GCM
	}
}

// trojanHexSha224 computes the SHA-224 hex key used by trojan protocol.
func trojanHexSha224(password string) []byte {
	// Replicates the exact logic from xray-core/proxy/trojan/config.go hexSha224
	h := sha256.New224()
	h.Write([]byte(password))
	buf := make([]byte, 56)
	hexEncode(buf, h.Sum(nil))
	return buf
}

// hexEncode is a minimal hex encoder (avoids importing encoding/hex).
func hexEncode(dst, src []byte) {
	const hextable = "0123456789abcdef"
	for i, v := range src {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
}

// ensureGeoData downloads geo databases when routes reference geoip/geosite.
func (x *Xray) ensureGeoData(nc *model.NodeSpec) {
	needIP, needSite := kernel.NeedsGeoIP(nc.Routes), kernel.NeedsGeoSite(nc.Routes)
	if !needIP && !needSite {
		return
	}
	dir := x.cfg.GeoDataDir
	if err := geodata.Ensure(dir, needIP, needSite, "xray"); err != nil {
		nlog.Core().Warn("geo database unavailable", "error", err)
	}
	os.Setenv("XRAY_LOCATION_ASSET", dir)
}

// marshalConfig builds the xray JSON config and returns the raw bytes.
func marshalConfig(cfg config.KernelConfig, nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) ([]byte, error) {
	cfgMap := buildConfig(cfg, nc, users, tls)
	data, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	nlog.Core().Debug("xray config generated", "len", len(data))
	return data, nil
}

// startWithTimeout runs instance.Start() with a bounded deadline.
func startWithTimeout(inst *xrayCore.Instance, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- inst.Start() }()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("start xray: %w", err)
		}
		return nil
	case <-time.After(timeout):
		go inst.Close()
		return fmt.Errorf("start xray: timeout after %v", timeout)
	}
}

// closeOld shuts down a previously running instance and its dispatcher.
// Recycling happens in a background goroutine to prevent the main thread
// from blocking on slow connection draining, enabling "hitless" reload.
func closeOld(inst *xrayCore.Instance, ld *LimitDispatcher) {
	if inst == nil {
		return
	}
	go func() {
		// 1. Drain connections gracefully (best effort, e.g. 5 minutes)
		// We use a much longer timeout here than the default Stop() because
		// it's running in background and doesn't block new user connections.
		if ld != nil {
			drainConns(ld, 5*time.Minute)
		}
		// 2. Hard close
		inst.Close()
		if ld != nil {
			ld.ResetConns()
		}
		nlog.Core().Debug("xray: old instance recycled")
	}()
}

// drainConns waits up to timeout for the dispatcher's active connections to
// reach zero. Used only during graceful Stop, not during hot-reload.
func drainConns(ld *LimitDispatcher, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ld.connCount.Load() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// aggregateStats is a fallback path that reads xray's built-in stats counters
// when LimitDispatcher is not available. Returns per-user cumulative traffic.
// Must be called with x.mu held.
func (x *Xray) aggregateStats() (map[int][2]int64, error) {
	sm := x.instance.GetFeature(stats.ManagerType())
	if sm == nil {
		return nil, nil
	}
	mgr, ok := sm.(stats.Manager)
	if !ok {
		return nil, nil
	}

	traffic := make(map[int][2]int64)
	for _, u := range x.users {
		email := userEmail(u.ID)

		var dUp, dDown int64
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>uplink", email)); c != nil {
			dUp = c.Set(0)
		}
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>downlink", email)); c != nil {
			dDown = c.Set(0)
		}

		if dUp > 0 || dDown > 0 {
			cum := x.cumTraffic[u.ID]
			cum[0] += dUp
			cum[1] += dDown
			x.cumTraffic[u.ID] = cum
		}

		if cum := x.cumTraffic[u.ID]; cum[0] > 0 || cum[1] > 0 {
			traffic[u.ID] = cum
		}
	}
	return traffic, nil
}

// updateDispatcherLimits configures the LimitDispatcher with per-user
// device-limit admission metadata and speed limiters. Speed is enforced by
// wrapping transport.Link.Writer only, keeping mux/XUDP Reader intact.
func (x *Xray) updateDispatcherLimits(users []model.UserSpec) {
	x.mu.Lock()
	ld := x.limitDispatcher
	fn := x.speedLimitFunc
	x.mu.Unlock()
	if ld == nil {
		return
	}

	emailToUID := make(map[string]int, len(users)*2)
	deviceLimits := make(map[string]int)
	speedLimiters := make(map[string]*rate.Limiter)

	for _, u := range users {
		email := userEmail(u.ID)
		emailToUID[email] = u.ID
		emailToUID[u.UUID] = u.ID
		if u.DeviceLimit > 0 {
			deviceLimits[email] = u.DeviceLimit
			deviceLimits[u.UUID] = u.DeviceLimit
		}
		var lim *rate.Limiter
		if fn != nil {
			lim = fn(u.UUID)
		} else if u.SpeedLimit > 0 {
			bps := int64(u.SpeedLimit) * 1_000_000 / 8
			if bps > 0 {
				lim = rate.NewLimiter(rate.Limit(bps), int(bps))
			}
		}
		if lim != nil {
			speedLimiters[email] = lim
			speedLimiters[u.UUID] = lim
		}
	}

	ld.UpdateLimits(emailToUID, deviceLimits, speedLimiters)
}

// xrayCreationMu serialises xrayCore.New() + globalLimitDispatcher capture
// so that concurrent Xray instances in multi-node mode each capture their
// own LimitDispatcher.
var xrayCreationMu sync.Mutex
