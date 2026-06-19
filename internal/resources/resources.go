package resources

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
)

type Level int

const (
	LevelOK Level = iota
	LevelCaution
	LevelCritical
)

func (l Level) String() string {
	switch l {
	case LevelOK:
		return "OK"
	case LevelCaution:
		return "CAUTION"
	case LevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type SystemStats struct {
	CPUCores       int
	LoadAvg1m      float64
	MemTotalMB     int64
	MemAvailableMB int64
	DiskFreeMB     int64
}

var (
	cpuCautionPct  = envFloat("ARES_CPU_CAUTION_PCT", 70)
	cpuCriticalPct = envFloat("ARES_CPU_CRITICAL_PCT", 90)
	ramCautionMB   = envInt64("ARES_RAM_CAUTION_MB", 1024)
	ramCriticalMB  = envInt64("ARES_RAM_CRITICAL_MB", 512)
	diskCautionMB  = envInt64("ARES_DISK_CAUTION_MB", 1024)
	diskCriticalMB = envInt64("ARES_DISK_CRITICAL_MB", 512)
	maxInstances   = envInt("ARES_MAX_INSTANCES", 10)
)

func GetStats() SystemStats {
	stats := SystemStats{CPUCores: runtime.NumCPU()}
	stats.LoadAvg1m = readLoadAvg()
	stats.MemTotalMB, stats.MemAvailableMB = readMemInfo()
	stats.DiskFreeMB = readDiskFree()
	return stats
}

func CurrentLevel() (Level, string) {
	stats := GetStats()
	level := LevelOK
	var reasons []string

	cpuCautionLoad := float64(stats.CPUCores) * cpuCautionPct / 100
	cpuCriticalLoad := float64(stats.CPUCores) * cpuCriticalPct / 100

	if stats.LoadAvg1m >= cpuCriticalLoad {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("CPU critical: load %.1f >= %.1f", stats.LoadAvg1m, cpuCriticalLoad))
	} else if stats.LoadAvg1m >= cpuCautionLoad {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("CPU high: load %.1f >= %.1f", stats.LoadAvg1m, cpuCautionLoad))
	}

	if stats.MemAvailableMB < ramCriticalMB {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("RAM critical: %d MB free < %d MB", stats.MemAvailableMB, ramCriticalMB))
	} else if stats.MemAvailableMB < ramCautionMB {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("RAM low: %d MB free < %d MB", stats.MemAvailableMB, ramCautionMB))
	}

	if stats.DiskFreeMB < diskCriticalMB {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("Disk critical: %d MB free < %d MB", stats.DiskFreeMB, diskCriticalMB))
	} else if stats.DiskFreeMB < diskCautionMB {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("Disk low: %d MB free < %d MB", stats.DiskFreeMB, diskCautionMB))
	}

	if len(reasons) == 0 {
		return LevelOK, fmt.Sprintf("OK - CPU: %.1f/%d, RAM: %d MB, Disk: %d MB", stats.LoadAvg1m, stats.CPUCores, stats.MemAvailableMB, stats.DiskFreeMB)
	}
	return level, strings.Join(reasons, "; ")
}

func CanAdmitScan(runningCount int) (bool, string) {
	if runningCount >= maxInstances {
		return false, fmt.Sprintf("limit: %d/%d instances", runningCount, maxInstances)
	}
	level, reason := CurrentLevel()
	if level >= LevelCaution {
		return false, reason
	}
	return true, reason
}

func CanExecTool(isHeavy bool) (bool, string) {
	level, reason := CurrentLevel()
	if isHeavy && level >= LevelCaution {
		return false, reason
	}
	if !isHeavy && level >= LevelCritical {
		return false, reason
	}
	return true, reason
}

func WaitForResources(isHeavy bool, maxWait time.Duration, toolName string) bool {
	deadline := time.Now().Add(maxWait)
	waited := false
	for time.Now().Before(deadline) {
		ok, _ := CanExecTool(isHeavy)
		if ok {
			if waited {
				logger.Error(fmt.Sprintf("[RESOURCES] Recovered - proceeding with %q", toolName))
			}
			return true
		}
		if !waited {
			_, reason := CurrentLevel()
			logger.Info(fmt.Sprintf("[THROTTLE] Waiting for %q - %s", toolName, reason))
			waited = true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

func MaxInstances() int {
	return maxInstances
}

func envFloat(key string, defaultVal float64) float64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return defaultVal
	}
	return v
}

func envInt64(key string, defaultVal int64) int64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultVal
	}
	return v
}

func envInt(key string, defaultVal int) int {
	return int(envInt64(key, int64(defaultVal)))
}

func maxLevel(a, b Level) Level {
	if a > b {
		return a
	}
	return b
}
