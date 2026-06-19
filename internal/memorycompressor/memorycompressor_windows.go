package memorycompressor

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func lockMemory(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	addr := uintptr(unsafe.Pointer(&data[0]))
	size := uintptr(len(data))
	err := windows.VirtualLock(addr, size)
	return err == nil
}

func unlockMemory(data []byte) {
	if len(data) == 0 {
		return
	}
	addr := uintptr(unsafe.Pointer(&data[0]))
	size := uintptr(len(data))
	windows.VirtualUnlock(addr, size)
}
