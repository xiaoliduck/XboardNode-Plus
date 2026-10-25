package singbox

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	"golang.org/x/time/rate"
)

func TestSingBoxCapabilities(t *testing.T) {
	s := New(config.KernelConfig{Type: "sing-box"})
	caps := s.Capabilities()
	if !caps.PerUserSpeedLimit || !caps.DeviceLimit || !caps.AliveIPTracking || !caps.ForceCloseUser {
		t.Fatalf("unexpected sing-box capabilities: %+v", caps)
	}
	if caps.BuiltInTrafficStats || caps.ForceCloseConnection {
		t.Fatalf("unexpected sing-box capabilities: %+v", caps)
	}
	protocols := s.Protocols()
	found := false
	for _, protocol := range protocols {
		if protocol == "hysteria" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Protocols() missing hysteria: %v", protocols)
	}
}

type testConn struct {
	closed bool
	reads  [][]byte
	writes [][]byte
}

func (c *testConn) Read(b []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, errors.New("eof")
	}
	chunk := c.reads[0]
	c.reads = c.reads[1:]
	n := copy(b, chunk)
	return n, nil
}

func (c *testConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	c.writes = append(c.writes, cp)
	return len(b), nil
}

func (c *testConn) Close() error                     { c.closed = true; return nil }
func (c *testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

func testInboundContext(uuid, ip string) adapter.InboundContext {
	return adapter.InboundContext{
		User:   uuid,
		Source: singM.Socksaddr{Addr: netip.MustParseAddr(ip)},
	}
}

func TestConnTrackerRoutedConnectionTracksTrafficAndAliveIPs(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{reads: [][]byte{[]byte("hello")}}

	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)

	buf := make([]byte, 16)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 5 {
		t.Fatalf("Read() bytes = %d, want 5", n)
	}
	if _, err := wrapped.Write([]byte("bye")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	traffic, aliveIPs, connCount := tracker.GetUserTraffic()
	if got := traffic[1]; got != [2]int64{5, 3} {
		t.Fatalf("traffic[1] = %v, want [5 3]", got)
	}
	events := tracker.FlushRecentAccess()
	if len(events) != 1 {
		t.Fatalf("FlushRecentAccess() returned %d events, want 1", len(events))
	}
	if events[0].SessionID == "" {
		t.Fatal("access event should include a session id")
	}
	if events[0].Upload != 5 || events[0].Download != 3 {
		t.Fatalf("access traffic = [%d %d], want [5 3]", events[0].Upload, events[0].Download)
	}
	if !aliveIPs[1]["1.1.1.1"] {
		t.Fatal("expected alive IP to include source address")
	}
	if connCount != 1 {
		t.Fatalf("connCount = %d, want 1", connCount)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, aliveIPs, connCount = tracker.GetUserTraffic()
	if aliveIPs[1] != nil {
		t.Fatalf("aliveIPs after close = %v, want nil", aliveIPs[1])
	}
	if connCount != 0 {
		t.Fatalf("connCount after close = %d, want 0", connCount)
	}
}

func TestConnTrackerRoutedConnectionRejectsWhenDeviceLimitExceeded(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(uuid string) (int, bool) {
		if uuid != "uuid-1" {
			return 0, false
		}
		return 1, true
	})

	first := &testConn{}
	wrapped1 := tracker.RoutedConnection(context.Background(), first, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	if wrapped1 == first {
		t.Fatal("expected first connection to be wrapped")
	}

	second := &testConn{}
	wrapped2 := tracker.RoutedConnection(context.Background(), second, testInboundContext("uuid-1", "2.2.2.2"), nil, nil)
	if wrapped2 != second {
		t.Fatal("expected rejected connection to be returned unwrapped")
	}
	if !second.closed {
		t.Fatal("expected rejected connection to be closed")
	}
}

func TestConnTrackerCheckDeviceGateMergesFreshGlobalDevices(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	us := tracker.users[1]
	us.addConn("1.1.1.1")
	tracker.UpdateGlobalDevices(map[int][]string{1: {"9.9.9.9"}})

	if !tracker.checkDeviceGate(us, 1, "2.2.2.2", 2) {
		t.Fatal("expected a third IPv4 to be rejected")
	}
	if !tracker.checkDeviceGate(us, 1, "99.99.99.99", 2) {
		t.Fatal("expected merged local+global device state to reject extra IPv4")
	}
	if tracker.checkDeviceGate(us, 1, "1.1.1.1", 2) {
		t.Fatal("existing local IP should still be allowed")
	}
	if tracker.checkDeviceGate(us, 1, "9.9.9.9", 2) {
		t.Fatal("existing global IP should still be allowed")
	}
}

func TestConnTrackerEvictsOverflowAfterGlobalSync(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(string) (int, bool) { return 0, false })

	keep := &testConn{}
	drop := &testConn{}
	if _, ok := tracker.RoutedConnection(context.Background(), keep, testInboundContext("uuid-1", "1.1.1.1"), nil, nil).(*trackedConn); !ok {
		t.Fatal("expected first connection to be tracked")
	}
	if _, ok := tracker.RoutedConnection(context.Background(), drop, testInboundContext("uuid-1", "9.9.9.9"), nil, nil).(*trackedConn); !ok {
		t.Fatal("expected second connection to be tracked before limit is enabled")
	}

	tracker.SetDeviceLimitFunc(func(string) (int, bool) { return 1, true })
	prevHold, prevGrace := deviceOverflowHold, deviceIPGrace
	deviceOverflowHold = 0
	deviceIPGrace = 0
	defer func() {
		deviceOverflowHold, deviceIPGrace = prevHold, prevGrace
	}()
	tracker.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1", "9.9.9.9"}})
	if !drop.closed {
		t.Fatal("expected extra IP 9.9.9.9 to be evicted")
	}
	if keep.closed {
		t.Fatal("expected keeper IP 1.1.1.1 to stay connected")
	}
}

func TestConnTrackerDualStackCountsAsOneDevice(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	us := tracker.users[1]
	us.addConn("1.1.1.1")
	if tracker.checkDeviceGate(us, 1, "2001:db8::1", 1) {
		t.Fatal("IPv6 alongside a single IPv4 should count as the same device")
	}
}

func TestConnTrackerDoesNotEvictDuringHold(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(string) (int, bool) { return 0, false })
	keep := &testConn{}
	drop := &testConn{}
	tracker.RoutedConnection(context.Background(), keep, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	tracker.RoutedConnection(context.Background(), drop, testInboundContext("uuid-1", "9.9.9.9"), nil, nil)
	tracker.SetDeviceLimitFunc(func(string) (int, bool) { return 1, true })
	tracker.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1", "9.9.9.9"}})
	if drop.closed || keep.closed {
		t.Fatal("overflow should wait before evicting live connections")
	}
}

func TestConnTrackerCloseByUUIDClosesTCPAndUDPForThatUserOnly(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})

	goneTCP := &testConn{}
	keepTCP := &testConn{}
	tracker.RoutedConnection(context.Background(), goneTCP, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	tracker.RoutedConnection(context.Background(), keepTCP, testInboundContext("uuid-2", "2.2.2.2"), nil, nil)

	goneUDP := &testPacketConn{}
	keepUDP := &testPacketConn{}
	tracker.RoutedPacketConnection(context.Background(), goneUDP, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	tracker.RoutedPacketConnection(context.Background(), keepUDP, testInboundContext("uuid-2", "2.2.2.2"), nil, nil)

	if got := tracker.CloseByUUID("uuid-1"); got != 2 {
		t.Fatalf("CloseByUUID() = %d, want 2", got)
	}
	if !goneTCP.closed || !goneUDP.closed {
		t.Fatal("expected removed user's TCP and UDP connections to close")
	}
	if keepTCP.closed || keepUDP.closed {
		t.Fatal("expected the other user's connections to stay open")
	}
	if got := tracker.CloseByUUID("missing"); got != 0 {
		t.Fatalf("CloseByUUID(missing) = %d, want 0", got)
	}
}

func TestConnTrackerRejectsRemovedUserAfterMapUpdate(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
	live := &testConn{}
	tracker.RoutedConnection(context.Background(), live, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)

	tracker.SetUserMap(map[string]int{"uuid-2": 2})
	again := &testConn{}
	tracker.RoutedConnection(context.Background(), again, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	if !again.closed {
		t.Fatal("expected a new connection from a removed user to be rejected")
	}
	if live.closed {
		t.Fatal("updating the user map must not close the remaining connection by itself")
	}
	if got := tracker.CloseByUUID("uuid-1"); got != 1 {
		t.Fatalf("CloseByUUID after removal = %d, want 1", got)
	}
	if !live.closed {
		t.Fatal("expected the removed user's existing connection to close")
	}
}

type testPacketConn struct {
	closed bool
}

func (c *testPacketConn) ReadPacket(*buf.Buffer) (singM.Socksaddr, error) {
	return singM.Socksaddr{}, errors.New("eof")
}
func (c *testPacketConn) WritePacket(*buf.Buffer, singM.Socksaddr) error { return nil }
func (c *testPacketConn) Close() error                                   { c.closed = true; return nil }
func (c *testPacketConn) LocalAddr() net.Addr                            { return &net.UDPAddr{} }
func (c *testPacketConn) SetDeadline(time.Time) error                    { return nil }
func (c *testPacketConn) SetReadDeadline(time.Time) error                { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error               { return nil }

func TestConnTrackerCloseByIDClosesTrackedConnection(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{}
	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	tracked, ok := wrapped.(*trackedConn)
	if !ok {
		t.Fatalf("wrapped type = %T, want *trackedConn", wrapped)
	}
	if !tracker.CloseByID(tracked.connID) {
		t.Fatal("CloseByID() = false, want true")
	}
	if !base.closed {
		t.Fatal("expected underlying connection to be closed")
	}
}

func TestConnTrackerRateLimitHonorsContextCancellation(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetSpeedLimitFunc(func(uuid string) *rate.Limiter {
		if uuid != "uuid-1" {
			return nil
		}
		return rate.NewLimiter(rate.Limit(1), 1)
	})

	readCtx, cancelRead := context.WithCancel(context.Background())
	readBase := &testConn{reads: [][]byte{[]byte("a"), []byte("a")}}
	readTracked := tracker.RoutedConnection(readCtx, readBase, testInboundContext("uuid-1", "1.1.1.1"), nil, nil).(*trackedConn)
	buf := make([]byte, 8)
	if n, err := readTracked.Read(buf); err != nil || n != 1 {
		t.Fatalf("first Read() = (%d, %v), want (1, nil)", n, err)
	}
	cancelRead()
	if n, err := readTracked.Read(buf); !errors.Is(err, context.Canceled) || n != 1 {
		t.Fatalf("second Read() = (%d, %v), want (1, context canceled)", n, err)
	}

	writeCtx, cancelWrite := context.WithCancel(context.Background())
	writeBase := &testConn{}
	writeTracked := tracker.RoutedConnection(writeCtx, writeBase, testInboundContext("uuid-1", "1.1.1.2"), nil, nil).(*trackedConn)
	if n, err := writeTracked.Write([]byte("a")); err != nil || n != 1 {
		t.Fatalf("first Write() = (%d, %v), want (1, nil)", n, err)
	}
	cancelWrite()
	if n, err := writeTracked.Write([]byte("a")); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("second Write() = (%d, %v), want (0, context canceled)", n, err)
	}
}
