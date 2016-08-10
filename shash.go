/*
Package shash contains a secured hash implementation. It works on top of a key-value
storage with Dao interface. All values are encrypted by AES 256.

Keys are not encrypted.

Key is created based on provided password with crypto-rand salt.

Example:

    dao := shash.NewInMemDao()  // implement your own DAO if use a DB
    sh, _ := shash.NewSecuredHash("password", dao)
    sh.Put([]byte("key"), []byte("value")) // saved, with value encrypted
    v, _ := sh.Get([]byte("key"))  // v is []byte("value")
    sh.Delete([]byte("key"))  // key is deleted

*/
package shash

import (
	"errors"
)

// SHash is a secured hash implentation on top of any key-value storage (see Dao
// interface).
type SHash struct {
	dao Dao
	key []byte
}

const (
	saltKey = "_salt_key_74469_"
)

// NewSecuredHash initializes new empty hash. Will create new salt. Will
// fail if salt already exists.
func NewSecuredHash(password string, dao Dao) (*SHash, error) {
	if password == "" {
		return nil, errors.New("No password is provided")
	}
	if dao == nil {
		return nil, errors.New("No DAO is provided")
	}
	existingSalt, err := dao.Get([]byte(saltKey))
	if err != nil {
		return nil, err
	}
	if existingSalt != nil {
		return nil, errors.New(
			"The data already exist. Use open with valid password")
	}
	key, salt, err := keyHash(password)
	if err != nil {
		return nil, err
	}
	err = dao.Put([]byte(saltKey), salt)
	if err != nil {
		return nil, err
	}
	return &SHash{dao, key}, nil
}

// Put encrypts value and sends it to dao with the key.
func (sh *SHash) Put(key, value []byte) error {
	encrypted, err := encrypt(sh.key, value)
	if err != nil {
		return err
	}
	return sh.dao.Put(key, encrypted)
}

// Get returns decrypted value for a key. Nil if no data exists or the password
// is wrong.
func (sh *SHash) Get(key []byte) ([]byte, error) {
	encrypted, err := sh.dao.Get(key)
	if err != nil {
		return nil, err
	}
	if encrypted == nil {
		return nil, nil
	}
	return decrypt(sh.key, encrypted)
}

// Delete removes key/value. Password is not checked for this step.
func (sh *SHash) Delete(key []byte) error {
	return sh.dao.Delete(key)
}
