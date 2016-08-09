package shash

import (
	"errors"
)

// SHash is secured hash implentation under any key-value storage (see Dao
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
