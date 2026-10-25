package singbox

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	sbanytls "github.com/sagernet/sing-box/protocol/anytls"
	sbshadowsocks "github.com/sagernet/sing-box/protocol/shadowsocks"
	sbtrojan "github.com/sagernet/sing-box/protocol/trojan"
	sbvless "github.com/sagernet/sing-box/protocol/vless"
	sbvmess "github.com/sagernet/sing-box/protocol/vmess"
)

func TestSwapVLESSUsersUpdatesServiceInPlace(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	inbound, err := sbvless.NewInbound(context.Background(), nil, logger, "vless-in", option.VLESSInboundOptions{
		Users: []option.VLESSUser{{
			Name: "11111111-1111-1111-1111-111111111111",
			UUID: "11111111-1111-1111-1111-111111111111",
		}, {
			Name: "22222222-2222-2222-2222-222222222222",
			UUID: "22222222-2222-2222-2222-222222222222",
		}},
	})
	if err != nil {
		t.Fatalf("NewInbound() error = %v", err)
	}

	kept := []option.VLESSUser{{
		Name: "22222222-2222-2222-2222-222222222222",
		UUID: "22222222-2222-2222-2222-222222222222",
	}}
	if err := swapVLESS(inbound, kept); err != nil {
		t.Fatalf("swapVLESS() error = %v", err)
	}

	usersField, ok := exportField(inbound, "users")
	if !ok {
		t.Fatal("vless inbound has no users field")
	}
	users, ok := usersField.Interface().([]option.VLESSUser)
	if !ok || len(users) != 1 || users[0].UUID != kept[0].UUID {
		t.Fatalf("users = %#v, want the kept user", usersField.Interface())
	}

	svcAny, err := servicePtr(inbound, "service")
	if err != nil {
		t.Fatal(err)
	}
	userMap, ok := exportField(svcAny, "userMap")
	if !ok {
		t.Fatal("vless service has no userMap")
	}
	if userMap.Len() != 1 {
		t.Fatalf("userMap len = %d, want 1", userMap.Len())
	}
}

func TestSwapCommonProtocolsKeepOneUser(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	ctx := context.Background()

	vmessIn, err := sbvmess.NewInbound(ctx, nil, logger, "vmess-in", option.VMessInboundOptions{
		Users: []option.VMessUser{
			{Name: "u1", UUID: "11111111-1111-1111-1111-111111111111"},
			{Name: "u2", UUID: "22222222-2222-2222-2222-222222222222"},
		},
	})
	if err != nil {
		t.Fatalf("vmess NewInbound() error = %v", err)
	}
	if err := swapVMess(vmessIn, []option.VMessUser{{Name: "u2", UUID: "22222222-2222-2222-2222-222222222222"}}); err != nil {
		t.Fatalf("swapVMess() error = %v", err)
	}
	if got := fieldLen(t, vmessIn, "users"); got != 1 {
		t.Fatalf("vmess users = %d, want 1", got)
	}

	trojanIn, err := sbtrojan.NewInbound(ctx, nil, logger, "trojan-in", option.TrojanInboundOptions{
		Users: []option.TrojanUser{
			{Name: "u1", Password: "password-1"},
			{Name: "u2", Password: "password-2"},
		},
	})
	if err != nil {
		t.Fatalf("trojan NewInbound() error = %v", err)
	}
	if err := swapTrojan(trojanIn, []option.TrojanUser{{Name: "u2", Password: "password-2"}}); err != nil {
		t.Fatalf("swapTrojan() error = %v", err)
	}
	if got := fieldLen(t, trojanIn, "users"); got != 1 {
		t.Fatalf("trojan users = %d, want 1", got)
	}

	anyIn, err := sbanytls.NewInbound(ctx, nil, logger, "anytls-in", option.AnyTLSInboundOptions{
		Users: []option.AnyTLSUser{
			{Name: "u1", Password: "password-1"},
			{Name: "u2", Password: "password-2"},
		},
	})
	if err != nil {
		t.Fatalf("anytls NewInbound() error = %v", err)
	}
	if err := swapAnyTLS(anyIn, []option.AnyTLSUser{{Name: "u2", Password: "password-2"}}); err != nil {
		t.Fatalf("swapAnyTLS() error = %v", err)
	}
	svc, err := servicePtr(anyIn, "service")
	if err != nil {
		t.Fatal(err)
	}
	if got := fieldLen(t, svc, "users"); got != 1 {
		t.Fatalf("anytls passwords = %d, want 1", got)
	}

	ssIn, err := sbshadowsocks.NewInbound(ctx, nil, logger, "ss-in", option.ShadowsocksInboundOptions{
		Method: "aes-256-gcm",
		Users: []option.ShadowsocksUser{
			{Name: "u1", Password: "password-1"},
			{Name: "u2", Password: "password-2"},
		},
	})
	if err != nil {
		t.Fatalf("shadowsocks NewInbound() error = %v", err)
	}
	handled, err := swapShadowsocks(ssIn, []option.ShadowsocksUser{{Name: "u2", Password: "password-2"}})
	if err != nil || !handled {
		t.Fatalf("swapShadowsocks() handled=%v error=%v", handled, err)
	}
	if got := fieldLen(t, ssIn, "users"); got != 1 {
		t.Fatalf("shadowsocks users = %d, want 1", got)
	}
}

func fieldLen(t *testing.T, target any, name string) int {
	t.Helper()
	field, ok := exportField(target, name)
	if !ok {
		t.Fatalf("%T has no %s", target, name)
	}
	return field.Len()
}

func TestSwapOfficialUsersIgnoresUnsupportedInbound(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	inbound, err := sbvless.NewInbound(context.Background(), nil, logger, "vless-in", option.VLESSInboundOptions{
		Users: []option.VLESSUser{{
			Name: "11111111-1111-1111-1111-111111111111",
			UUID: "11111111-1111-1111-1111-111111111111",
		}},
	})
	if err != nil {
		t.Fatalf("NewInbound() error = %v", err)
	}
	handled, err := swapOfficialUsers(inbound, option.Inbound{Options: &option.SocksInboundOptions{}})
	if err != nil {
		t.Fatalf("swapOfficialUsers() error = %v", err)
	}
	if handled {
		t.Fatal("socks options must not be treated as a vless user swap")
	}
}
