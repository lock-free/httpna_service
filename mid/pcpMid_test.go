package mid

import (
	"errors"
	"fmt"
	"strings"
	"testing"
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

func TestResponseToBytes(t *testing.T) {
	bytes := ResponseToBytes(PcpHttpResponse{1, 123, "err"})
	assertEqual(t, strings.TrimSpace(string(bytes)), `{"text":1,"errno":123,"errMsg":"err"}`, "")
}

func TestErrorToResponse(t *testing.T) {
	assertEqual(t, ErrorToResponse(errors.New("errrr")), PcpHttpResponse{nil, 530, "errrr"}, "")
	assertEqual(t, ErrorToResponse(&HttpError{566, "e!!!"}), PcpHttpResponse{nil, 566, "e!!!"}, "")
}
