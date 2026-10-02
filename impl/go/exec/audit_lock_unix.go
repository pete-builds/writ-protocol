//go:build unix

package exec

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on the audit record, so processes that
// share it append one linked entry at a time.
func lockFile(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
}
