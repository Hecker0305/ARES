// Package nessus provides integration with Tenable Nessus Vulnerability Scanner
// through the Nessus REST API (v6/v8/v10). It supports session-based authentication
// and API key authentication, scan lifecycle management, policy management,
// vulnerability retrieval, export operations, and forensic artifact collection.
//
// Features:
//   - Session-based and API key authentication
//   - Full scan CRUD operations (create, launch, pause, resume, stop, delete)
//   - Policy and folder management
//   - Vulnerability enumeration and filtering (by severity, plugin family)
//   - Export scans to Nessus, CSV, HTML, and PDF formats
//   - High-level scan workflows (quick, full, custom, credentialed)
//   - Legacy Nessus 6.x compatibility
//   - Forensic artifact analysis for incident response
package nessus
