package shash

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
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

func keyHashWithSalt(password string, salt []byte) ([]byte, error) {
	if len(salt) != keyLen {
		return nil, errors.New("Salt has wrong size")
	}
	input := append([]byte(password), salt...)
	hash := sha256.Sum256(input)
	return hash[:], nil
}
