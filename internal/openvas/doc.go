// Package openvas provides integration with OpenVAS / Greenbone Vulnerability
// Management (GVM) through the Greenbone Management Protocol (GMP) over SSH
// or TLS. It supports task lifecycle management, target creation, report
// retrieval, NVT enumeration, and forensic artifact collection.
//
// Features:
//   - GMP XML-based protocol communication over SSH or TLS
//   - Full authentication via <authenticate> command
//   - Task CRUD operations (create, start, stop, delete)
//   - Target management with host and port specifications
//   - Report and result retrieval with severity filtering
//   - NVT (Network Vulnerability Test) enumeration
//   - High-level scan workflows (quick, full, comprehensive)
//   - Feed synchronization and version information
//   - Forensic artifact analysis for incident response
package openvas
