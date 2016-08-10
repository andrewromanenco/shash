package shash

import "testing"

func TestInMemPut(t *testing.T) {
	testee := NewInMemDao()
	testee.Put([]byte("key"), []byte("value"))
	if testee.m["key"] == nil {
		t.Error("Put must write to internal map")
	}
}

func TestInMemGet(t *testing.T) {
	testee := NewInMemDao()
	testee.m["key"] = []byte("value")
	value, _ := testee.Get([]byte("key"))
	if value == nil {
		t.Error("Get must read from internal map")
	}
}

func TestInMemDelete(t *testing.T) {
	testee := NewInMemDao()
	testee.m["key"] = []byte("value")
	testee.Delete([]byte("key"))
	if testee.m["key"] != nil {
		t.Error("Delete must remove key from internal map")
	}
}
