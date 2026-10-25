package singbox

import (
	"fmt"
	"reflect"
	"unsafe"

	anytls "github.com/anytls/sing-anytls"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	trojan "github.com/sagernet/sing-box/transport/trojan"
	hysteria "github.com/sagernet/sing-quic/hysteria"
	hysteria2 "github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
)

// swapOfficialUsers updates an official sing-box inbound's user table without
// restarting the instance. The protocol service is unexported, so the swap
// reaches it through the field address. Restarting would close every
// connection on the node, including users who were not removed.
func swapOfficialUsers(existing adapter.Inbound, inb option.Inbound) (bool, error) {
	switch opts := inb.Options.(type) {
	case *option.VLESSInboundOptions:
		return true, swapVLESS(existing, opts.Users)
	case *option.VMessInboundOptions:
		return true, swapVMess(existing, opts.Users)
	case *option.TrojanInboundOptions:
		return true, swapTrojan(existing, opts.Users)
	case *option.Hysteria2InboundOptions:
		return true, swapHysteria2(existing, opts.Users)
	case *option.HysteriaInboundOptions:
		return true, swapHysteria(existing, opts.Users)
	case *option.TUICInboundOptions:
		return true, swapTUIC(existing, opts.Users)
	case *option.AnyTLSInboundOptions:
		return true, swapAnyTLS(existing, opts.Users)
	case *option.ShadowsocksInboundOptions:
		return swapShadowsocks(existing, opts.Users)
	default:
		return false, nil
	}
}

func swapVLESS(inbound adapter.Inbound, users []option.VLESSUser) error {
	svcAny, err := servicePtr(inbound, "service")
	if err != nil {
		return err
	}
	svc, ok := svcAny.(*vless.Service[int])
	if !ok || svc == nil {
		return fmt.Errorf("vless service type %T", svcAny)
	}
	copied := append([]option.VLESSUser(nil), users...)
	idx, uuids, flows := make([]int, len(copied)), make([]string, len(copied)), make([]string, len(copied))
	for i, user := range copied {
		idx[i] = i
		uuids[i] = user.UUID
		flows[i] = user.Flow
	}
	svc.UpdateUsers(idx, uuids, flows)
	return setField(inbound, "users", copied)
}

func swapVMess(inbound adapter.Inbound, users []option.VMessUser) error {
	svcAny, err := servicePtr(inbound, "service")
	if err != nil {
		return err
	}
	svc, ok := svcAny.(*vmess.Service[int])
	if !ok || svc == nil {
		return fmt.Errorf("vmess service type %T", svcAny)
	}
	copied := append([]option.VMessUser(nil), users...)
	idx, uuids, alters := make([]int, len(copied)), make([]string, len(copied)), make([]int, len(copied))
	for i, user := range copied {
		idx[i] = i
		uuids[i] = user.UUID
		alters[i] = user.AlterId
	}
	if err := svc.UpdateUsers(idx, uuids, alters); err != nil {
		return err
	}
	return setField(inbound, "users", copied)
}

func swapTrojan(inbound adapter.Inbound, users []option.TrojanUser) error {
	svcAny, err := servicePtr(inbound, "service")
	if err != nil {
		return err
	}
	svc, ok := svcAny.(*trojan.Service[int])
	if !ok || svc == nil {
		return fmt.Errorf("trojan service type %T", svcAny)
	}
	copied := append([]option.TrojanUser(nil), users...)
	idx, passwords := make([]int, len(copied)), make([]string, len(copied))
	for i, user := range copied {
		idx[i] = i
		passwords[i] = user.Password
	}
	if err := svc.UpdateUsers(idx, passwords); err != nil {
		return err
	}
	return setField(inbound, "users", copied)
}

func swapHysteria2(inbound adapter.Inbound, users []option.Hysteria2User) error {
	svcAny, err := servicePtr(inbound, "service")
	if err != nil {
		return err
	}
	svc, ok := svcAny.(*hysteria2.Service[int])
	if !ok || svc == nil {
		return fmt.Errorf("hysteria2 service type %T", svcAny)
	}
	idx, names, passwords := make([]int, len(users)), make([]string, len(users)), make([]string, len(users))
	for i, user := range users {
		idx[i] = i
		names[i] = user.Name
		passwords[i] = user.Password
	}
	svc.UpdateUsers(idx, passwords)
	return setField(inbound, "userNameList", names)
}

func swapHysteria(inbound adapter.Inbound, users []option.HysteriaUser) error {
	svcAny, err := servicePtr(inbound, "service")
	if err != nil {
		return err
	}
	svc, ok := svcAny.(*hysteria.Service[int])
	if !ok || svc == nil {
		return fmt.Errorf("hysteria service type %T", svcAny)
	}
	idx, names, passwords := make([]int, len(users)), make([]string, len(users)), make([]string, len(users))
	for i, user := range users {
		idx[i] = i
		names[i] = user.Name
		if user.AuthString != "" {
			passwords[i] = user.AuthString
		} else {
			passwords[i] = string(user.Auth)
		}
	}
	svc.UpdateUsers(idx, passwords)
	return setField(inbound, "userNameList", names)
}

func swapTUIC(inbound adapter.Inbound, users []option.TUICUser) error {
	svcAny, err := servicePtr(inbound, "server")
	if err != nil {
		return err
	}
	svc, ok := svcAny.(*tuic.Service[int])
	if !ok || svc == nil {
		return fmt.Errorf("tuic service type %T", svcAny)
	}
	idx := make([]int, len(users))
	names := make([]string, len(users))
	ids := make([][16]byte, len(users))
	passwords := make([]string, len(users))
	for i, user := range users {
		id, err := uuid.FromString(user.UUID)
		if err != nil {
			return fmt.Errorf("tuic user %d: %w", i, err)
		}
		idx[i] = i
		names[i] = user.Name
		ids[i] = id
		passwords[i] = user.Password
	}
	svc.UpdateUsers(idx, ids, passwords)
	return setField(inbound, "userNameList", names)
}

func swapAnyTLS(inbound adapter.Inbound, users []option.AnyTLSUser) error {
	svcAny, err := servicePtr(inbound, "service")
	if err != nil {
		return err
	}
	svc, ok := svcAny.(*anytls.Service)
	if !ok || svc == nil {
		return fmt.Errorf("anytls service type %T", svcAny)
	}
	copied := make([]anytls.User, len(users))
	for i, user := range users {
		copied[i] = anytls.User{Name: user.Name, Password: user.Password}
	}
	svc.UpdateUsers(copied)
	return nil
}

func swapShadowsocks(existing adapter.Inbound, users []option.ShadowsocksUser) (bool, error) {
	updater, ok := existing.(interface {
		UpdateUsers(users []string, uPSKs []string) error
	})
	if !ok {
		return false, nil
	}
	names := make([]string, len(users))
	keys := make([]string, len(users))
	for i, user := range users {
		names[i] = user.Name
		keys[i] = user.Password
	}
	return true, updater.UpdateUsers(names, keys)
}

func servicePtr(inbound adapter.Inbound, field string) (any, error) {
	f, ok := exportField(inbound, field)
	if !ok {
		return nil, fmt.Errorf("%T has no %s", inbound, field)
	}
	if f.Kind() != reflect.Pointer || f.IsNil() {
		return nil, fmt.Errorf("%T.%s is nil", inbound, field)
	}
	return f.Interface(), nil
}

func setField(target any, name string, value any) error {
	f, ok := exportField(target, name)
	if !ok {
		return fmt.Errorf("%T has no %s", target, name)
	}
	v := reflect.ValueOf(value)
	if !v.IsValid() || !v.Type().AssignableTo(f.Type()) {
		return fmt.Errorf("%T.%s: cannot assign %T", target, name, value)
	}
	copied := v
	if v.Kind() == reflect.Slice {
		copied = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(copied, v)
	}
	f.Set(copied)
	return nil
}

func exportField(target any, name string) (reflect.Value, bool) {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return reflect.Value{}, false
	}
	f := v.Elem().FieldByName(name)
	if !f.IsValid() || !f.CanAddr() {
		return reflect.Value{}, false
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem(), true
}
