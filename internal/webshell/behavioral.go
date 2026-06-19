package webshell

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type fileInfo struct {
	path        string
	name        string
	size        int64
	modTime     time.Time
	perm        os.FileMode
	md5         string
	sha256      string
	extension   string
	isInWebRoot bool
	isInUpload  bool
}

func collectFileInfo(path string, webRoots []string, uploadDirs []string) (*fileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	info := &fileInfo{
		path:      path,
		name:      fi.Name(),
		size:      fi.Size(),
		modTime:   fi.ModTime(),
		perm:      fi.Mode().Perm(),
		extension: ext,
	}

	absPath, _ := filepath.Abs(path)
	for _, root := range webRoots {
		absRoot, _ := filepath.Abs(root)
		if strings.HasPrefix(strings.ToLower(absPath), strings.ToLower(absRoot)) {
			info.isInWebRoot = true
			break
		}
	}

	dir := filepath.Dir(absPath)
	dirLower := strings.ToLower(dir)
	for _, ud := range uploadDirs {
		if strings.Contains(dirLower, strings.ToLower(ud)) {
			info.isInUpload = true
			break
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return info, nil
	}
	defer f.Close()

	md5h := md5.New()
	sha256h := sha256.New()
	multi := io.MultiWriter(md5h, sha256h)
	io.CopyN(multi, f, 1<<20)
	info.md5 = hex.EncodeToString(md5h.Sum(nil))
	info.sha256 = hex.EncodeToString(sha256h.Sum(nil))

	return info, nil
}

func hasExecutablePerm(info *fileInfo) bool {
	return info.perm&0111 != 0
}

func hasDoubleExtension(name string) bool {
	parts := strings.Split(name, ".")
	return len(parts) >= 3
}

func isScriptExtension(ext string) bool {
	scriptExts := map[string]bool{
		".php": true, ".php5": true, ".phtml": true, ".php7": true, ".php8": true,
		".asp": true, ".aspx": true, ".ashx": true, ".asmx": true,
		".jsp": true, ".jspx": true, ".do": true,
		".py": true, ".pl": true, ".cgi": true,
		".shtml": true, ".shtm": true,
	}
	return scriptExts[ext]
}

func isRecentlyModified(info *fileInfo, threshold time.Duration) bool {
	return time.Since(info.modTime) < threshold
}

func isExecutableScriptInUpload(info *fileInfo) (bool, string) {
	if !info.isInUpload {
		return false, ""
	}
	if !isScriptExtension(info.extension) {
		return false, ""
	}
	return true, fmt.Sprintf("executable script %s in upload directory", info.name)
}

func checkBehavioralIndicators(info *fileInfo) []Finding {
	var findings []Finding

	if hasExecutablePerm(info) && isScriptExtension(info.extension) {
		if info.isInWebRoot || info.isInUpload {
			findings = append(findings, Finding{
				FilePath:        info.path,
				FileName:        info.name,
				Language:        detectLanguage(info.extension),
				Severity:        SeverityLow,
				Confidence:      0.4,
				DetectionMethod: MethodBehavior,
				FileSize:        info.size,
				ModifiedAt:      info.modTime,
				Permissions:     fmt.Sprintf("%o", info.perm),
				Evidence:        fmt.Sprintf("executable permissions on script file in web-accessible directory: %o", info.perm),
			})
		}
	}

	if hasDoubleExtension(info.name) && isScriptExtension(info.extension) {
		findings = append(findings, Finding{
			FilePath:        info.path,
			FileName:        info.name,
			Language:        detectLanguage(info.extension),
			Severity:        SeverityMedium,
			Confidence:      0.6,
			DetectionMethod: MethodBehavior,
			FileSize:        info.size,
			ModifiedAt:      info.modTime,
			Evidence:        fmt.Sprintf("double extension detected: %s", info.name),
		})
	}

	recentThreshold := 24 * time.Hour
	if isRecentlyModified(info, recentThreshold) && isScriptExtension(info.extension) && info.isInWebRoot {
		findings = append(findings, Finding{
			FilePath:        info.path,
			FileName:        info.name,
			Language:        detectLanguage(info.extension),
			Severity:        SeverityLow,
			Confidence:      0.3,
			DetectionMethod: MethodBehavior,
			FileSize:        info.size,
			ModifiedAt:      info.modTime,
			Evidence:        fmt.Sprintf("script file modified within last %v in web root", recentThreshold),
		})
	}

	if found, evidence := isExecutableScriptInUpload(info); found {
		findings = append(findings, Finding{
			FilePath:        info.path,
			FileName:        info.name,
			Language:        detectLanguage(info.extension),
			Severity:        SeverityHigh,
			Confidence:      0.7,
			DetectionMethod: MethodBehavior,
			FileSize:        info.size,
			ModifiedAt:      info.modTime,
			Evidence:        evidence,
		})
	}

	return findings
}

func detectLanguage(ext string) Language {
	switch ext {
	case ".php", ".php5", ".phtml", ".php7", ".php8":
		return LangPHP
	case ".asp":
		return LangASP
	case ".aspx", ".ashx", ".asmx":
		return LangASPX
	case ".jsp", ".jspx":
		return LangJSP
	case ".py":
		return LangPython
	case ".pl", ".cgi":
		return LangPerl
	default:
		return LangGeneric
	}
}
