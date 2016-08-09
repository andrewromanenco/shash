package shash

import (
	"crypto/rand"
	"crypto/sha256"
)

const (
	keyLen = 32
)

func keyHash(password string) ([]byte, []byte, error) {
	salt := make([]byte, keyLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}
	input := append([]byte(password), salt...)
	hash := sha256.Sum256(input)
	return hash[:], salt, nil
}
