package frame

import (
	"bytes"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{TypeDataPayload, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte("not a frame"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ReadFrame(bytes.NewReader(b)) })
}
