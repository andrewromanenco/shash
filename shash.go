/*
Package shash contains a secured hash implementation. It works on top of a key-value storage with Dao interface and provides values encryption.


## Cryptographic key

Values are encrypted with AES 256. This symmetric algorithm requires 256 bit crypto key to operate. To make security stronger and avoid dictionary attack, next steps are executed to convert a string password to a 256 bit crypto key:

 - 32 crypto rand bytes are generated (this is not the same as Math.rand)
 - password string gets converted into a byte slice
 - 32 random bytes get appended to password bytes
 - sha256 is used to convert the result byte sequence into a 32 byte crypto key

Crypto key has 256 bits. Salt (32 random bytes) is random, but there is no need to keep it in secret.


## Encrypt/Decrypt

AES 256 is used for values encryption/decryption.


### Encryption process

 - get input bytes and calculate CRC32 (4 bytes checksum)
 - append CRC32 to the input
 - encrypt input with provided key


### Decryption process

 - get input bytes and decrypt them with provided key
 - get output and cut off last 4
 - calculate CRC32 for the output
 - compare calculated CRC32 with bytes cutted on the second step
 - fail if CRC does not match, or return output


## Hash operations and encryption

**SHash** supports standard hash operations: put(key, value), get(key), delete(key). Put and Get encrypt/decrypt values in background. **THEY DO NOT ENCRYPT HASH KEY**.


## Initialization and persistence

Both creating and opening a secured hash requires two parameters: password and a dao. Dao is an interface and may provide persistence for encrypted values. Reference implementation (InMemDao) is provided, it is based on standard golang map.


## Salt

It is important to remember that salt is not a secret, but should not be lost. If salt is lost, the data is lost as well (even if the password is known). To handle salt persistence, it is stored in a provided dao.

**NewSecuredHash(...)** initiates a secured hash on top of a provided dao, with salt generation. This function will fail if salt is already in the dao.

**OpenSecuredHash(...)** opens secured storage on top of a provided dao. Salt from the dao is reused for crypto-key generation. If the dao has no salt, this function will fail.


## Handle an invalid password

**Shash** does not check on open if a password is valid. This check is up to higher code layer. For example, a program may save random value for known key: ```Put(constant-key-name, random-value)```. After OpenSecuredHash, call to ```Get(constant-key-name)```, for an invalid password, Get operation will fail.


## Example


	import (
	"fmt"
	"github.com/andrewromanenco/shash"
	)

	dao := getMyDao()  // implementation of Dao interface
	// dao := shash.NewInMemDao() for example, use reference one
	sh,_ := shash.NewSecuredHash("my-password", dao)
	sh.Put([]byte("key"), []byte("value"))
	v, _ := sh.Get([]byte("key"))
	fmt.Println(v)  // prints bytes for value
	sh.Delete([]byte("key"))
	v, _ = sh.Get([]byte("key"))
	fmt.Println(v)  // prints empty value (does not exist)


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

// OpenSecuredHash creates secured hash on top of dao with salt already
// initialized. Fails if no salt yet.
func OpenSecuredHash(password string, dao Dao) (*SHash, error) {
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
	if existingSalt == nil {
		return nil, errors.New(
			"No salt, use NewSecuredHash")
	}
	key, err := keyHashWithSalt(password, existingSalt)
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
