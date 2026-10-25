package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/accesslog"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Local copies of cedar2025/sing-box hot-update interfaces. Official sing-box
// does not export these types; if an inbound implements UpdateUsers the
// type-assert still succeeds. Otherwise swapOfficialUsers updates the
// unexported protocol service. The instance restarts only when neither works.
type updatableInbound[T any] interface {
	UpdateUsers(users []T) error
}

type updatableShadowsocksInbound interface {
	UpdateUsersByOptions(users []option.ShadowsocksUser) error
}

// hotUpdateInbounds reports whether every inbound accepted a credential swap.
// A false result means the caller must restart the instance. Official
// sing-box inbounds keep their user service unexported; swapOfficialUsers
// updates that service in place so other users stay connected.
func hotUpdateInbounds(im adapter.InboundManager, inbounds []option.Inbound) bool {
	for _, inb := range inbounds {
		existing, ok := im.Get(inb.Tag)
		if !ok || existing.Type() != inb.Type {
			return false
		}
		handled, err := applyInboundUsers(existing, inb)
		if !handled || err != nil {
			if err != nil {
				nlog.Core().Warn("incremental user update failed", "tag", inb.Tag, "error", err)
			}
			return false
		}
	}
	return true
}

func applyInboundUsers(existing adapter.Inbound, inb option.Inbound) (handled bool, err error) {
	switch v := existing.(type) {
	case updatableInbound[option.VMessUser]:
		opts, ok := inb.Options.(*option.VMessInboundOptions)
		if !ok {
			return true, fmt.Errorf("unexpected vmess inbound options")
		}
		return true, v.UpdateUsers(opts.Users)
	case updatableInbound[option.VLESSUser]:
		opts, ok := inb.Options.(*option.VLESSInboundOptions)
		if !ok {
			return true, fmt.Errorf("unexpected vless inbound options")
		}
		return true, v.UpdateUsers(opts.Users)
	case updatableInbound[option.TrojanUser]:
		opts, ok := inb.Options.(*option.TrojanInboundOptions)
		if !ok {
			return true, fmt.Errorf("unexpected trojan inbound options")
		}
		return true, v.UpdateUsers(opts.Users)
	case updatableInbound[option.Hysteria2User]:
		opts, ok := inb.Options.(*option.Hysteria2InboundOptions)
		if !ok {
			return true, fmt.Errorf("unexpected hysteria2 inbound options")
		}
		return true, v.UpdateUsers(opts.Users)
	case updatableShadowsocksInbound:
		opts, ok := inb.Options.(*option.ShadowsocksInboundOptions)
		if !ok {
			return true, fmt.Errorf("unexpected shadowsocks inbound options")
		}
		return true, v.UpdateUsersByOptions(opts.Users)
	case updatableInbound[option.TUICUser]:
		opts, ok := inb.Options.(*option.TUICInboundOptions)
		if !ok {
			return true, fmt.Errorf("unexpected tuic inbound options")
		}
		return true, v.UpdateUsers(opts.Users)
	case updatableInbound[option.AnyTLSUser]:
		opts, ok := inb.Options.(*option.AnyTLSInboundOptions)
		if !ok {
			return true, fmt.Errorf("unexpected anytls inbound options")
		}
		return true, v.UpdateUsers(opts.Users)
	case updatableInbound[auth.User]:
		switch opts := inb.Options.(type) {
		case *option.NaiveInboundOptions:
			return true, v.UpdateUsers(opts.Users)
		case *option.SocksInboundOptions:
			return true, v.UpdateUsers(opts.Users)
		case *option.HTTPMixedInboundOptions:
			return true, v.UpdateUsers(opts.Users)
		default:
			return false, nil
		}
	default:
		return swapOfficialUsers(existing, inb)
	}
}

// SingBox implements kernel.Kernel by embedding sing-box as a Go library.
//
// User operations try UpdateUsers when an inbound implements it. Official
// sing-box 1.14.4 keeps that method on an unexported service, which
// swapOfficialUsers updates in place. Listener and route changes still
// restart the instance, because InboundManager no longer exposes Remove or Close.
type SingBox struct {
	cfg config.KernelConfig

	mu     sync.RWMutex
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc

	users      []model.UserSpec
	nodeConfig *model.NodeSpec
	tls        kernel.TLSCert

	// connTracker is our lightweight in-process byte/IP tracker.
	// Created fresh on every Start (full restart).
	// Survives Reload (hot-swap) since live connections persist.
	connTracker *ConnTracker

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	// Set once by SetSpeedLimitFunc and forwarded to every new ConnTracker.
	speedLimitFunc func(string) *rate.Limiter

	// deviceLimitFunc resolves a user UUID to (limit, hasLimit) for gate-keeping.
	// Set once by SetDeviceLimitFunc and forwarded to every new ConnTracker.
	deviceLimitFunc func(string) (int, bool)

	// trackerRegistered prevents duplicate AppendTracker calls on the same
	// Router instance during Reload. Reset to false on full restart.
	trackerRegistered bool
}

func New(cfg config.KernelConfig) *SingBox {
	return &SingBox{cfg: cfg}
}

var _ kernel.Kernel = (*SingBox)(nil)

func (s *SingBox) Name() string { return "sing-box" }

func (s *SingBox) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  false,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       true,
	}
}

func (s *SingBox) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "tuic", "naive", "socks", "http", "anytls",
	}
}

func (s *SingBox) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked(nodeConfig, users, tls)
}

func (s *SingBox) startLocked(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	nlog.Core().Debug("sing-box config generated", "len", len(data))

	ctx, cancel := context.WithCancel(context.Background())
	ctx = include.Context(ctx)

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		return fmt.Errorf("parse sing-box options: %w", err)
	}

	// Save old state before creating the new instance.
	oldBox := s.box
	oldCancel := s.cancel

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("create sing-box instance: %w", err)
	}

	// 1.14.4 closes listen sockets only from Box.Close. Release the previous
	// instance before binding, otherwise the new process cannot take the port.
	if oldBox != nil {
		_ = oldBox.Close()
		if oldCancel != nil {
			oldCancel()
		}
	}

	if err := instance.Start(); err != nil {
		_ = instance.Close()
		cancel()
		s.box = nil
		s.ctx = nil
		s.cancel = nil
		return fmt.Errorf("start sing-box: %w", err)
	}

	// New instance started successfully — swap state.
	s.box = instance
	s.ctx = ctx
	s.cancel = cancel
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls

	// Fresh tracker on full restart.
	s.connTracker = NewConnTracker(0)
	s.connTracker.SetUserMap(buildUserMap(users))
	if s.speedLimitFunc != nil {
		s.connTracker.SetSpeedLimitFunc(s.speedLimitFunc)
	}
	if s.deviceLimitFunc != nil {
		s.connTracker.SetDeviceLimitFunc(s.deviceLimitFunc)
	}

	s.trackerRegistered = false
	s.registerTracker(ctx)

	nlog.Core().Debug("sing-box started", "users", len(users))
	return nil
}

// Reload hot-swaps the inbound users and routing rules without restarting the box.
// Routes, outbounds, and the connTracker stay alive so in-flight connections
// continue to be tracked correctly.
func (s *SingBox) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return fmt.Errorf("not running")
	}

	// Official sing-box has no Router.UpdateRules. Route/outbound changes
	// require a new instance; inbound-only user updates stay hot.
	if routingConfigChanged(s.nodeConfig, nodeConfig) {
		nlog.Core().Info("sing-box routing or outbounds changed, restarting instance")
		return s.startLocked(nodeConfig, users, tls)
	}

	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	// Configuration hash check for inbound reconstruction
	tlsChanged := !bytes.Equal(s.tls.CertPEM, tls.CertPEM) || !bytes.Equal(s.tls.KeyPEM, tls.KeyPEM)
	configChanged := tlsChanged || s.nodeConfig == nil || kernel.ComputeHash(nodeConfig, users) != kernel.ComputeHash(s.nodeConfig, s.users)

	if configChanged || !hotUpdateInbounds(im, opts.Inbounds) {
		nlog.Core().Info("sing-box inbound cannot be replaced in place, restarting instance")
		return s.startLocked(nodeConfig, users, tls)
	}

	// Trackers remain registered on the Router (which survives ReloadUsers).
	// Only update the user map — do NOT re-register or traffic is double-counted.
	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
	}

	nlog.Core().Debug("sing-box reloaded", "users", len(users))
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	return nil
}

// registerTracker wires the ConnTracker to the current Router exactly once.
// The ConnTracker handles both byte counting and optional rate limiting
// in a single wrapper, so no additional trackers are needed.
func (s *SingBox) registerTracker(ctx context.Context) {
	if s.trackerRegistered {
		return
	}
	router := service.FromContext[adapter.Router](ctx)
	if router == nil {
		return
	}
	if s.connTracker != nil {
		router.AppendTracker(s.connTracker)
	}
	s.trackerRegistered = true
}

func (s *SingBox) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
}

func (s *SingBox) stop() {
	if s.box == nil {
		return
	}

	// Box.Close tears down the scope, including listen sockets. 1.14.4 has no
	// separate inbound Close, so listeners and the rest stop together.
	_ = s.box.Close()
	s.box = nil
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.ctx = nil
}

func (s *SingBox) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.box != nil
}

// connTrackerLocked returns the connTracker under a read-optimised lock.
func (s *SingBox) connTrackerSafe() *ConnTracker {
	s.mu.Lock()
	ct := s.connTracker
	s.mu.Unlock()
	return ct
}

// SetSpeedLimitFunc configures per-user bandwidth throttling.
func (s *SingBox) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.speedLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetSpeedLimitFunc(fn)
	}
}

// SetDeviceLimitFunc configures per-user device limit gate-keeping.
// Connections exceeding the limit are rejected at connect time.
func (s *SingBox) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetDeviceLimitFunc(fn)
	}
}

// UpdateGlobalDevices updates the global device state from panel (for multi-node).
func (s *SingBox) UpdateGlobalDevices(users map[int][]string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.UpdateGlobalDevices(users)
	}
}

// ClearGlobalDevices clears the global device state (on WS disconnect).
func (s *SingBox) ClearGlobalDevices() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.ClearGlobalDevices()
	}
}

// ─── User management (non-disruptive) ───────────────────────────────────────

// AddUsers applies users to running inbounds, restarting the instance when
// the inbound cannot hot-swap credentials.
func (s *SingBox) AddUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	existing := make(map[int]struct{}, len(s.users))
	for _, u := range s.users {
		existing[u.ID] = struct{}{}
	}
	var toAdd []model.UserSpec
	for _, u := range users {
		if _, dup := existing[u.ID]; !dup {
			toAdd = append(toAdd, u)
		}
	}
	if len(toAdd) == 0 {
		return 0, nil
	}

	merged := append(append([]model.UserSpec{}, s.users...), toAdd...)
	if err := s.reloadInboundsLocked(merged); err != nil {
		return 0, err
	}
	s.users = merged
	return len(toAdd), nil
}

// RemoveUsers drops users from running inbounds, restarting the instance when
// the inbound cannot hot-swap credentials.
// for remaining users.
func (s *SingBox) RemoveUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []model.UserSpec
	removed := 0
	for _, u := range s.users {
		if _, rm := removeSet[u.ID]; rm {
			removed++
		} else {
			kept = append(kept, u)
		}
	}
	if removed == 0 {
		return 0, nil
	}

	if err := s.reloadInboundsLocked(kept); err != nil {
		return 0, err
	}
	s.users = kept
	return removed, nil
}

// UpdateUsers replaces the entire user set, restarting the instance when
// inbounds cannot hot-swap credentials.
func (s *SingBox) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, 0, fmt.Errorf("not running")
	}

	toAdd, toRemove := kernel.UserDiff(s.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		// Only limits may have changed — update tracker map.
		if s.connTracker != nil {
			s.connTracker.SetUserMap(buildUserMap(users))
		}
		s.users = users
		return 0, 0, nil
	}

	if err = s.reloadInboundsLocked(users); err != nil {
		return 0, 0, err
	}
	s.users = users
	return
}

// reloadInboundsLocked applies inbound users using UpdatableInbound.
// Must be called with s.mu held. Official sing-box restarts instead.
func (s *SingBox) reloadInboundsLocked(users []model.UserSpec) error {
	cfgMap := buildConfig(s.cfg, s.nodeConfig, users, s.tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	if !hotUpdateInbounds(im, opts.Inbounds) {
		nlog.Core().Info("sing-box inbound cannot hot-swap users, restarting instance")
		return s.startLocked(s.nodeConfig, users, s.tls)
	}

	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
	}

	nlog.Core().Debug("sing-box users hot-swapped", "users", len(users))
	return nil
}

// ─── Observability ──────────────────────────────────────────────────────────
func (s *SingBox) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil, nil, 0, nil
	}
	traffic, aliveIPs, connCount = ct.GetUserTraffic()
	return traffic, aliveIPs, connCount, nil
}

func (s *SingBox) FlushRecentAccess() []accesslog.Event {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil
	}
	return ct.FlushRecentAccess()
}

// CloseConnection force-closes a specific connection by its ID.
func (s *SingBox) CloseConnection(_ context.Context, connID string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return fmt.Errorf("not running")
	}
	if !ct.CloseByID(connID) {
		nlog.Core().Debug("CloseConnection: connection not found (already closed?)", "id", connID)
	}
	return nil
}

// CloseUserConnections terminates all connections for a user UUID.
func (s *SingBox) CloseUserConnections(_ context.Context, uuid string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil
	}
	ct.CloseByUUID(uuid)
	return nil
}

// buildUserMap creates a UUID→userID mapping used by ConnTracker to attribute
// connections to the correct user. All sing-box protocols use the user's UUID
// as the inbound name/username, so this covers every protocol.
func routingConfigChanged(old, neu *model.NodeSpec) bool {
	if old == nil || neu == nil {
		return old != neu
	}
	type routing struct {
		Routes           []model.RouteRule
		CustomOutbounds  []model.OutboundConfig
		CustomRoutes     []map[string]any
		CustomRouteRules []model.CustomRouteRule
	}
	a, _ := json.Marshal(routing{old.Routes, old.CustomOutbounds, old.CustomRoutes, old.CustomRouteRules})
	b, _ := json.Marshal(routing{neu.Routes, neu.CustomOutbounds, neu.CustomRoutes, neu.CustomRouteRules})
	return !bytes.Equal(a, b)
}

func buildUserMap(users []model.UserSpec) map[string]int {
	m := make(map[string]int, len(users))
	for _, u := range users {
		m[u.UUID] = u.ID
	}
	return m
}
