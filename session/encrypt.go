package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	plaintextbytes := []byte(plaintext)
	cipherStr := base64.StdEncoding.EncodeToString(aesgcm.Seal(nonce, nonce, plaintextbytes, nil))
	return cipherStr, nil
}

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func Decrypt(key []byte, text string) (string, error) {
	ciphertext, derr := base64.StdEncoding.DecodeString(text)
	if derr != nil {
		return "", derr
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		return "", err
	}

	nonceSize := aesgcm.NonceSize()

	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)

	return string(plaintext), err
}
