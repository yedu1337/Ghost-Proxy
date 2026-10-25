package padding

import "testing"

func FuzzUnpad(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 3, 1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Unpad(b) })
}
