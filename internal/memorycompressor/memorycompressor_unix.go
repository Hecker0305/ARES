//go:build !windows

package memorycompressor

func lockMemory(data []byte) bool {
	return false
}

func unlockMemory(data []byte) {}
