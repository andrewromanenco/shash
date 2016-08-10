package shash

// NewInMemDao return dao implementation based on standard map.
func NewInMemDao() *InMemDao {
	return &InMemDao{make(map[string][]byte)}
}

// InMemDao dao implementation based on map.
type InMemDao struct {
	m map[string][]byte
}

// Put saves key/value to internal map.
func (imd *InMemDao) Put(key, value []byte) error {
	imd.m[string(key)] = value
	return nil
}

// Get returns value by key from internal map.
func (imd *InMemDao) Get(key []byte) ([]byte, error) {
	return imd.m[string(key)], nil
}

// Delete removes key from internal map.
func (imd *InMemDao) Delete(key []byte) error {
	delete(imd.m, string(key))
	return nil
}
