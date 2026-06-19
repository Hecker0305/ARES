//go:build !windows

package resources

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/ares/engine/internal/logger"
)

func readLoadAvg() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return val
}

func readMemInfo() (totalMB, availableMB int64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		logger.Info(fmt.Sprintf("[RESOURCES] Cannot read /proc/meminfo: %v", err))
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalMB = val / 1024
		case "MemAvailable:":
			availableMB = val / 1024
		}
	}
	return totalMB, availableMB
}

func readDiskFree() int64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0
	}
	return int64(stat.Bavail) * int64(stat.Bsize) / (1024 * 1024)
}
