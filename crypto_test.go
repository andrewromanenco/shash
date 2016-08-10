package shash

import (
	"reflect"
	"testing"
)

func TestValidCRC(t *testing.T) {
	data := []byte("test-data")
	crcd := appendCRC(data)
	if len(data)+4 != len(crcd) {
		t.Error("Looks like CRC was not added")
	}
	result := validateCRC(crcd)
	if result == nil {
		t.Error("CRC validation failed")
	}
	if !reflect.DeepEqual(data, result) {
		t.Error("Data does not match original")
	}
}

func TestWrongCRCFails(t *testing.T) {
	data := []byte("test-data")
	result := validateCRC(data)
	if result != nil {
		t.Error("CRC validation must fail")
	}
}

func TestEncryptDecryptWorks(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("test-data")
	encrypted, err := encrypt(key, data)
	if err != nil {
		t.Error("Encryption step failed")
	}
	if reflect.DeepEqual(data, encrypt) {
		t.Error("Data was not encrypted")
	}
	decrypted, err := decrypt(key, encrypted)
	if err != nil {
		t.Error("Decryption step failed")
	}
	if !reflect.DeepEqual(data, decrypted) {
		t.Error("Data was not decrypted")
	}
}

func TestDecryptFailsOnWrongPassword(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("test-data")
	encrypted, err := encrypt(key, data)
	if err != nil {
		t.Error("Encryption step failed")
	}
	if reflect.DeepEqual(data, encrypt) {
		t.Error("Data was not encrypted")
	}
	otherKey := []byte("abcabcabcabcabcabcabcabcabcabcab")
	_, err = decrypt(otherKey, encrypted)
	if err == nil {
		t.Error("Encryption must fail with wrong password")
	}
}
