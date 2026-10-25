package panel

import (
	"encoding/json"
	"strconv"
)

// parseDeviceUsers accepts the several shapes Xboard has sent as
// sync.devices "users": map[userID][]string, PHP objects with holes,
// or a list of {id, ips} / {ip} maps.
func parseDeviceUsers(raw interface{}) map[int][]string {
	out := make(map[int][]string)
	if raw == nil {
		return out
	}
	switch v := raw.(type) {
	case map[string]interface{}:
		for k, val := range v {
			id, err := strconv.Atoi(k)
			if err != nil {
				continue
			}
			if ips := parseIPList(val); len(ips) > 0 {
				out[id] = ips
			}
		}
	case []interface{}:
		for i, item := range v {
			switch it := item.(type) {
			case map[string]interface{}:
				id := firstInt(it["id"], it["user_id"], it["uid"])
				ips := parseIPList(it["ips"])
				if len(ips) == 0 {
					ips = parseIPList(it["devices"])
				}
				if len(ips) == 0 {
					ips = parseIPList(it["ip"])
				}
				if id == 0 {
					id = i
				}
				if id > 0 && len(ips) > 0 {
					out[id] = ips
				}
			default:
				if ips := parseIPList(item); len(ips) > 0 && i > 0 {
					out[i] = ips
				}
			}
		}
	case json.Number:
	}
	return out
}

func parseIPList(v interface{}) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []string:
		return append([]string(nil), x...)
	case []interface{}:
		ips := make([]string, 0, len(x))
		for _, e := range x {
			switch t := e.(type) {
			case string:
				if t != "" {
					ips = append(ips, t)
				}
			case map[string]interface{}:
				if ip := firstString(t["ip"], t["IP"], t["address"], t["src"]); ip != "" {
					ips = append(ips, ip)
				}
			}
		}
		return ips
	case map[string]interface{}:
		ips := make([]string, 0, len(x))
		for _, e := range x {
			switch t := e.(type) {
			case string:
				if t != "" {
					ips = append(ips, t)
				}
			case map[string]interface{}:
				if ip := firstString(t["ip"], t["IP"], t["address"]); ip != "" {
					ips = append(ips, ip)
				}
			}
		}
		return ips
	default:
		return nil
	}
}

func firstInt(vals ...interface{}) int {
	for _, v := range vals {
		switch n := v.(type) {
		case int:
			if n != 0 {
				return n
			}
		case int64:
			if n != 0 {
				return int(n)
			}
		case float64:
			if n != 0 {
				return int(n)
			}
		case json.Number:
			i, _ := n.Int64()
			if i != 0 {
				return int(i)
			}
		case string:
			i, err := strconv.Atoi(n)
			if err == nil && i != 0 {
				return i
			}
		}
	}
	return 0
}

func firstString(vals ...interface{}) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
