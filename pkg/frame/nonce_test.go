package frame

import (
	"bytes"
	"sync"
	"testing"
)

func TestNonceCounterUniqueness(t *testing.T) {
	nc, err := NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter failed: %v", err)
	}

	seen := make(map[[NonceSize]byte]bool)

	for i := 0; i < 10000; i++ {
		nonce := nc.Next()

		if seen[nonce] {
			t.Fatalf("nonce repeated at iteration %d: %x", i, nonce)
		}

		seen[nonce] = true
	}
}

func TestNonceCounterMonotonicCounterPortion(t *testing.T) {
	nc, err := NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter failed: %v", err)
	}

	first := nc.Next()
	second := nc.Next()

	if !bytes.Equal(first[:4], second[:4]) {
		t.Error("salt portion (first 4 bytes) changed between calls")
	}

	if first == second {
		t.Error("counter portion did not change between calls")
	}
}

func TestNewNonceCounterDistinctSalts(t *testing.T) {
	nc1, err := NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter failed: %v", err)
	}

	nc2, err := NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter failed: %v", err)
	}

	if nc1.Next() == nc2.Next() {
		t.Error("two independently created NonceCounters produced the same first nonce")
	}
}

func TestNonceCounterConcurrentUse(t *testing.T) {
	nc, err := NewNonceCounter()
	if err != nil {
		t.Fatalf("NewNonceCounter failed: %v", err)
	}

	const goroutines = 50
	const perGoroutine = 200

	results := make(chan [NonceSize]byte, goroutines*perGoroutine)

	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for j := 0; j < perGoroutine; j++ {
				results <- nc.Next()
			}
		}()
	}

	wg.Wait()
	close(results)

	seen := make(map[[NonceSize]byte]bool)

	for nonce := range results {
		if seen[nonce] {
			t.Fatalf("nonce collision under concurrent use: %x", nonce)
		}

		seen[nonce] = true
	}

	if len(seen) != goroutines*perGoroutine {
		t.Errorf("expected %d unique nonces, got %d", goroutines*perGoroutine, len(seen))
	}
}
