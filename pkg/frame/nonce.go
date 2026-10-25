// Nonce generation for the framed protocol.
//
// Per the wire format spec, every frame carries a unique 12-byte nonce
// "derived from incremental counters to prevent reuse attacks." A
// NonceCounter combines a random 4-byte per-connection salt (chosen once,
// at creation) with an 8-byte big-endian monotonic counter: the salt
// keeps nonces from colliding across independent connections sharing a
// key, and the counter keeps them from repeating within one connection.
package frame

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

// NonceCounter generates unique 12-byte nonces for one direction of one
// connection. It is safe for concurrent use. Create one NonceCounter per
// direction (client->server, server->client) so two peers sharing a key
// never reuse a nonce.
type NonceCounter struct {
	salt    [4]byte
	counter uint64
}

// NewNonceCounter creates a NonceCounter with a fresh random salt.
func NewNonceCounter() (*NonceCounter, error) {
	nc := &NonceCounter{}

	if _, err := rand.Read(nc.salt[:]); err != nil {
		return nil, fmt.Errorf("frame: generate nonce salt: %w", err)
	}

	return nc, nil
}

// Next returns the next nonce in the sequence. It never repeats for the
// lifetime of nc, short of exhausting a 64-bit counter.
func (nc *NonceCounter) Next() [NonceSize]byte {
	count := atomic.AddUint64(&nc.counter, 1) - 1

	var nonce [NonceSize]byte
	copy(nonce[:4], nc.salt[:])
	binary.BigEndian.PutUint64(nonce[4:], count)

	return nonce
}
