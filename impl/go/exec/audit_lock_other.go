//go:build !unix

package exec

import "os"

// lockFile is a no-op where the platform has no flock: appends from one
// process are still serialized by AuditLog's mutex, but two processes
// sharing one record can fork its chain, which VerifyAudit then reports.
func lockFile(f *os.File) (func(), error) { return func() {}, nil }
