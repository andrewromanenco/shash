package shash

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"io"
)

func encrypt(key, data []byte) ([]byte, error) {
	data = appendCRC(data)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func appendCRC(data []byte) []byte {
	crc := crc32.ChecksumIEEE([]byte(data))
	crcb := []byte{byte((crc >> 24) & 0xFF),
		byte((crc >> 16) & 0xFF),
		byte((crc >> 8) & 0xFF),
		byte(crc & 0xFF)}
	return append(data, crcb...)
}

func decrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data, data)
	data = validateCRC(data)
	if data == nil {
		return nil, errors.New("Wrong password. CRC fail.")
	}
	return data, nil
}

func validateCRC(data []byte) []byte {
	if len(data) < 5 {
		return nil
	}
	crcb := append([]byte(nil), data[len(data)-4:]...)
	message := data[:len(data)-4]
	reappended := appendCRC(message)
	if !bytes.Equal(crcb, reappended[len(reappended)-4:]) {
		return nil
	}
	return message
}
