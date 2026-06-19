package diff

import (
	"bytes"
	"fmt"
	"strings"
)

type DiffType int

const (
	DiffEqual DiffType = iota
	DiffAdded
	DiffRemoved
	DiffModified
)

type Diff struct {
	Type    DiffType
	Old     string
	New     string
	LineNum int
}

func (d Diff) String() string {
	switch d.Type {
	case DiffAdded:
		return fmt.Sprintf("+ %s", d.New)
	case DiffRemoved:
		return fmt.Sprintf("- %s", d.Old)
	case DiffModified:
		return fmt.Sprintf("~ %s -> %s", d.Old, d.New)
	default:
		return fmt.Sprintf("  %s", d.Old)
	}
}

func NormalizeResponse(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		normalized = append(normalized, strings.TrimSpace(line))
	}
	return strings.Join(normalized, "\n")
}

func CompareStrings(old, new string) []Diff {
	oldNorm := NormalizeResponse(old)
	newNorm := NormalizeResponse(new)
	oldLines := strings.Split(oldNorm, "\n")
	newLines := strings.Split(newNorm, "\n")
	return compareLines(oldLines, newLines)
}

func CompareStringsInline(old, new string) []Diff {
	oldNorm := NormalizeResponse(old)
	newNorm := NormalizeResponse(new)
	var diffs []Diff
	if oldNorm == newNorm {
		return diffs
	}

	if oldNorm == "" {
		diffs = append(diffs, Diff{Type: DiffAdded, New: newNorm})
		return diffs
	}
	if newNorm == "" {
		diffs = append(diffs, Diff{Type: DiffRemoved, Old: oldNorm})
		return diffs
	}

	oldWords := strings.Fields(oldNorm)
	newWords := strings.Fields(newNorm)
	lineDiffs := lcsDiff(oldWords, newWords)

	for _, d := range lineDiffs {
		diffs = append(diffs, Diff{
			Type: DiffModified,
			Old:  d.Old,
			New:  d.New,
		})
	}
	return diffs
}

func CompareStringsNormalized(old, new string) ([]Diff, bool) {
	oldNorm := NormalizeResponse(old)
	newNorm := NormalizeResponse(new)
	if oldNorm == newNorm {
		return nil, true
	}
	return CompareStrings(old, new), false
}

func compareLines(oldLines, newLines []string) []Diff {
	var diffs []Diff
	lcs := computeLCS(oldLines, newLines)

	i, j, k := 0, 0, 0
	for i < len(oldLines) || j < len(newLines) {
		if k < len(lcs) && i < len(oldLines) && j < len(newLines) &&
			oldLines[i] == lcs[k] && newLines[j] == lcs[k] {
			diffs = append(diffs, Diff{Type: DiffEqual, Old: oldLines[i], LineNum: i + 1})
			i++
			j++
			k++
		} else if k < len(lcs) && i < len(oldLines) && oldLines[i] == lcs[k] {
			diffs = append(diffs, Diff{Type: DiffAdded, New: newLines[j], LineNum: j + 1})
			j++
		} else if k < len(lcs) && j < len(newLines) && newLines[j] == lcs[k] {
			diffs = append(diffs, Diff{Type: DiffRemoved, Old: oldLines[i], LineNum: i + 1})
			i++
		} else if i < len(oldLines) && j < len(newLines) {
			diffs = append(diffs, Diff{Type: DiffModified, Old: oldLines[i], New: newLines[j], LineNum: i + 1})
			i++
			j++
		} else if i < len(oldLines) {
			diffs = append(diffs, Diff{Type: DiffRemoved, Old: oldLines[i], LineNum: i + 1})
			i++
		} else if j < len(newLines) {
			diffs = append(diffs, Diff{Type: DiffAdded, New: newLines[j], LineNum: j + 1})
			j++
		}
	}

	return diffs
}

func computeLCS(a, b []string) []string {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	lcs := make([]string, 0, dp[m][n])
	i, j := m, n
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] {
			lcs = append([]string{a[i-1]}, lcs...)
			i--
			j--
		} else if dp[i-1][j] >= dp[i][j-1] {
			i--
		} else {
			j--
		}
	}
	return lcs
}

func lcsDiff(oldWords, newWords []string) []Diff {
	m, n := len(oldWords), len(newWords)
	if m == 0 && n == 0 {
		return nil
	}
	if m == 0 {
		return []Diff{{Type: DiffAdded, New: strings.Join(newWords, " ")}}
	}
	if n == 0 {
		return []Diff{{Type: DiffRemoved, Old: strings.Join(oldWords, " ")}}
	}

	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if oldWords[i-1] == newWords[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	var diffs []Diff
	i, j := m, n
	for i > 0 && j > 0 {
		if oldWords[i-1] == newWords[j-1] {
			diffs = append([]Diff{{Type: DiffEqual, Old: oldWords[i-1], New: newWords[j-1]}}, diffs...)
			i--
			j--
		} else if dp[i-1][j] >= dp[i][j-1] {
			diffs = append([]Diff{{Type: DiffRemoved, Old: oldWords[i-1]}}, diffs...)
			i--
		} else {
			diffs = append([]Diff{{Type: DiffAdded, New: newWords[j-1]}}, diffs...)
			j--
		}
	}
	for i > 0 {
		diffs = append([]Diff{{Type: DiffRemoved, Old: oldWords[i-1]}}, diffs...)
		i--
	}
	for j > 0 {
		diffs = append([]Diff{{Type: DiffAdded, New: newWords[j-1]}}, diffs...)
		j--
	}

	return diffs
}

func FormatDiffs(diffs []Diff, contextLines int) string {
	if contextLines < 0 {
		contextLines = 0
	}

	var buf bytes.Buffer
	for i, d := range diffs {
		switch d.Type {
		case DiffAdded:
			buf.WriteString(fmt.Sprintf("+%s\n", d.New))
		case DiffRemoved:
			buf.WriteString(fmt.Sprintf("-%s\n", d.Old))
		case DiffModified:
			buf.WriteString(fmt.Sprintf("-%s\n", d.Old))
			buf.WriteString(fmt.Sprintf("+%s\n", d.New))
		default:
			if contextLines > 0 {
				buf.WriteString(fmt.Sprintf(" %s\n", d.Old))
			}
		}

		if i < len(diffs)-1 && diffs[i+1].Type != DiffEqual && d.Type == DiffEqual {
			buf.WriteString("---\n")
		}
	}
	return buf.String()
}

func CountChanges(diffs []Diff) (added, removed, modified int) {
	for _, d := range diffs {
		switch d.Type {
		case DiffAdded:
			added++
		case DiffRemoved:
			removed++
		case DiffModified:
			modified++
		}
	}
	return
}
