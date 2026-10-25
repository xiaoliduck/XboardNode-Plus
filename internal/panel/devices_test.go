package panel

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestParseDeviceUsersMapOfStrings(t *testing.T) {
	raw := map[string]interface{}{
		"17": []interface{}{"1.1.1.1", "2.2.2.2"},
		"9":  []interface{}{"8.8.8.8"},
	}
	got := parseDeviceUsers(raw)
	if !reflect.DeepEqual(got[17], []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatalf("user 17 = %#v", got[17])
	}
	if !reflect.DeepEqual(got[9], []string{"8.8.8.8"}) {
		t.Fatalf("user 9 = %#v", got[9])
	}
}

func TestParseDeviceUsersPHPObjectHoles(t *testing.T) {
	raw := map[string]interface{}{
		"17": map[string]interface{}{"0": "1.1.1.1", "2": "9.9.9.9"},
	}
	got := parseDeviceUsers(raw)
	sort.Strings(got[17])
	if !reflect.DeepEqual(got[17], []string{"1.1.1.1", "9.9.9.9"}) {
		t.Fatalf("user 17 = %#v", got[17])
	}
}

func TestParseDeviceUsersListOfIPObjects(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{"id": 17.0, "ips": []interface{}{map[string]interface{}{"ip": "3.3.3.3"}}},
	}
	got := parseDeviceUsers(raw)
	if !reflect.DeepEqual(got[17], []string{"3.3.3.3"}) {
		t.Fatalf("user 17 = %#v", got[17])
	}
}

func TestParseDeviceUsersJSONRoundTrip(t *testing.T) {
	payload := []byte(`{"users":{"17":[{"ip":"4.4.4.4"}]}}`)
	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	got := parseDeviceUsers(raw["users"])
	if !reflect.DeepEqual(got[17], []string{"4.4.4.4"}) {
		t.Fatalf("got %#v", got)
	}
}
