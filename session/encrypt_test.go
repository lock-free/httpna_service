package session

import (
	"fmt"
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

func TestBaseEncrypt(t *testing.T) {
	text, key := "123", []byte("aaaaaaaaaaaaaaaa")

	ciphertext, err := Encrypt(key, text)
	if err != nil {
		panic(err)
	}
	stext, err := Decrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}

	assertEqual(t, text, stext, "")
}
