package uuid

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
)

var fallbackCounter int64

func New() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		n := atomic.AddInt64(&fallbackCounter, 1)
		return fmt.Sprintf("ffffffff-ffff-ffff-ffff-%012x", n)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
