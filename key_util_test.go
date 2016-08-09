package shash

import (
	"reflect"
	"testing"
)

func TestKeyHashReturnsKeyAndSalt(t *testing.T) {
	password := "qwerty"
	key, salt, err := keyHash(password)
	if err != nil {
		t.Error("Key hash should not fail", err)
	}
	if key == nil {
		t.Error("Key must not be nil")
	}
	if len(key) != 32 {
		t.Error("Key must be exactly 32 bytes")
	}
	if salt == nil {
		t.Error("Salt must not be nil")
	}
	if len(salt) != 32 {
		t.Error("Salt must be exactly 32 bytes")
	}
}

func TestHashingSamePwdReturnsDifferentKeyAndSalt(t *testing.T) {
	password := "qwerty"
	key1, salt1, _ := keyHash(password)
	key2, salt2, _ := keyHash(password)
	if reflect.DeepEqual(key1, key2) {
		t.Error("Same key is returned")
	}
	if reflect.DeepEqual(salt1, salt2) {
		t.Error("Same salt is returned")
	}
}
