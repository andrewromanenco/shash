package shash

import (
	"testing"
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
