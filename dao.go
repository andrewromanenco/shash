package shash

// Dao is an interface to a persistence storage layer
type Dao interface {
	// Puts saves given value for ta key; if key exists, the value gets overriden
	Put(key, value []byte) error

	// Get returns a value for a given key; or nil if there is nothing there
	Get(key []byte) ([]byte, error)

	// Delete removes a key
	Delete(key []byte) error
}
