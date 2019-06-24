package httpna

import (
	"fmt"
	"testing"
	"time"
)

func assertEqual(t *testing.T, expect interface{}, actual interface{}, message string) {
	if expect == actual {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("expect %v !=  actual %v", expect, actual)
	}
	t.Fatal(message)
}

func TestParseProxyCallExp(t *testing.T) {
	st, fn, ps, to, err := ParseProxyCallExp([]interface{}{"user-service", []interface{}{"getUser", "test"}, 120.0})
	assertEqual(t, st, "user-service", "")
	assertEqual(t, fn, "getUser", "")
	assertEqual(t, len(ps), 1, "")
	assertEqual(t, ps[0], "test", "")
	assertEqual(t, err, nil, "")
	assertEqual(t, to, time.Duration(120)*time.Second, "")
}

func TestParseDownloadCallExp(t *testing.T) {
	st, fn, ps, _, to, err := ParseDownloadCallExp([]interface{}{"user-service", []interface{}{"getUser", "test"}, make(map[string]interface{}), 120.0})
	assertEqual(t, st, "user-service", "")
	assertEqual(t, fn, "getUser", "")
	assertEqual(t, len(ps), 1, "")
	assertEqual(t, ps[0], "test", "")
	assertEqual(t, err, nil, "")
	assertEqual(t, to, time.Duration(120)*time.Second, "")
}
