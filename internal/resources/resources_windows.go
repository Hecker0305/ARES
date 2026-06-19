//go:build windows

package resources

import (
	"fmt"
	"unsafe"

	"github.com/ares/engine/internal/logger"
	"golang.org/x/sys/windows"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func readLoadAvg() float64 {
	var idle, kernel, user windows.Filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		logger.Error(fmt.Sprintf("[RESOURCES] GetSystemTimes failed"))
		return 0
	}
	idleTime := uint64(idle.HighDateTime)<<32 | uint64(idle.LowDateTime)
	kernelTime := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	userTime := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	totalTime := kernelTime + userTime
	if totalTime == 0 {
		return 0
	}
	return 1.0 - float64(idleTime)/float64(totalTime)
}

func readMemInfo() (totalMB, availableMB int64) {
	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))
	if ret == 0 {
		logger.Error(fmt.Sprintf("[RESOURCES] GlobalMemoryStatusEx failed"))
		return 0, 0
	}
	totalMB = int64(mem.TotalPhys / (1024 * 1024))
	availableMB = int64(mem.AvailPhys / (1024 * 1024))
	return totalMB, availableMB
}

func readDiskFree() int64 {
	var freeBytesAvailableToCaller, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	err := windows.GetDiskFreeSpaceEx(nil, &freeBytesAvailableToCaller, &totalNumberOfBytes, &totalNumberOfFreeBytes)
	if err != nil {
		logger.Error(fmt.Sprintf("[RESOURCES] GetDiskFreeSpaceEx failed: %v", err))
		return 0
	}
	return int64(freeBytesAvailableToCaller / (1024 * 1024))
}
