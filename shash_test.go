package shash

import (
	"testing"
)

const (
	key   = "key"
	value = "value"
)

type mockDao struct {
	m map[string][]byte
}

func (md *mockDao) Put(key, value []byte) error {
	md.m[string(key)] = value
	return nil
}

func (md *mockDao) Get(key []byte) ([]byte, error) {
	return md.m[string(key)], nil
}

func (md *mockDao) Delete(key []byte) error {
	delete(md.m, string(key))
	return nil
}

func newMockDao() *mockDao {
	return &mockDao{make(map[string][]byte)}
}

func TestNewSHFailsIfPasswordEmpty(t *testing.T) {
	_, err := NewSecuredHash("", newMockDao())
	if err == nil {
		t.Error("Must fail for empty password")
	}
}

func TestNewSHFailsIfDaoNotProvided(t *testing.T) {
	_, err := NewSecuredHash("password", nil)
	if err == nil {
		t.Error("Must fail when dao not provided")
	}
}

func TestNewSHMustCreateSaltInDao(t *testing.T) {
	dao := newMockDao()
	testee, err := NewSecuredHash("password", dao)
	if err != nil {
		t.Error("No errors are expected")
	}
	if testee == nil {
		t.Error("Valid shash must be created")
	}
	if dao.m["_salt_key_74469_"] == nil {
		t.Error("Salt must be sent to DAO")
	}
}

func TestNewSHMustFailIfSaltAlreadyExists(t *testing.T) {
	dao := newMockDao()
	dao.m["_salt_key_74469_"] = []byte("salt-value")
	_, err := NewSecuredHash("password", dao)
	if err == nil {
		t.Error("Must fail when salt value exists")
	}
}

func initTestee() (*mockDao, *SHash) {
	dao := newMockDao()
	testee, _ := NewSecuredHash("password", dao)
	testee.Put([]byte(key), []byte(value))
	return dao, testee
}

func TestPut(t *testing.T) {
	dao, _ := initTestee()
	if dao.m[key] == nil {
		t.Error("Data was not sent to dao")
	}
	if string(dao.m[key]) == value {
		t.Error("Value was not encrypted before saving")
	}
}

func TestGetExistingValue(t *testing.T) {
	_, testee := initTestee()
	result, err := testee.Get([]byte(key))
	if err != nil {
		t.Error("Get should not retutn an error")
	}
	if string(result) != value {
		t.Error("Get did not return same value")
	}
}

func TestGetNonExistingValue(t *testing.T) {
	_, testee := initTestee()
	result, err := testee.Get([]byte("no-such-key"))
	if err != nil {
		t.Error("Get should not retutn an error")
	}
	if result != nil {
		t.Error("Nil must be returned for non existing key")
	}
}

func TestPutOverridesOldValue(t *testing.T) {
	_, testee := initTestee()
	otherValue := "other-value"
	testee.Put([]byte(key), []byte(otherValue))
	result, _ := testee.Get([]byte(key))
	if string(result) != otherValue {
		t.Error("Get did not return last value")
	}
}

func TestDeleteWorks(t *testing.T) {
	dao, testee := initTestee()
	testee.Delete([]byte(key))
	if dao.m[key] != nil {
		t.Error("Delete must remove key/value from dao")
	}
}

func TestDeleteDoesNotFailOnNonExistingKey(t *testing.T) {
	_, testee := initTestee()
	err := testee.Delete([]byte(key))
	if err != nil {
		t.Error("Delete must not return error")
	}
}
