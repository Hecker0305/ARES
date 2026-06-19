package agent

// UnverifiedCount returns the number of unverified findings (thread-safe).
func (sc *ScanContext) UnverifiedCount() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return len(sc.UnverifiedFindings)
}

// ConfirmedCount returns the number of confirmed findings (thread-safe).
func (sc *ScanContext) ConfirmedCount() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return len(sc.ConfirmedFindings)
}
