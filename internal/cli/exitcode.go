package cli

import (
	"errors"
	"fmt"
)

// Exit codes are part of the public interface and must remain stable.
const (
	ExitOK       = 0 // scan completed, no finding reached --fail-on
	ExitFindings = 1 // at least one finding reached the --fail-on threshold
	ExitUsage    = 2 // invalid arguments or flags
	ExitInput    = 3 // input could not be read or parsed, or exceeded limits
	ExitNetwork  = 4 // DNS or network failure prevented a reliable result
	ExitInternal = 5 // unexpected internal error
)

// exitError carries an exit code through cobra's error return path.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func withCode(code int, err error) error {
	return &exitError{code: code, err: err}
}

func usageErrorf(format string, args ...any) error {
	return withCode(ExitUsage, fmt.Errorf(format, args...))
}

// silentExit reports an exit code without printing an error message. It is
// used when the report itself already communicates the outcome.
func silentExit(code int) error {
	return &exitError{code: code}
}

// ExitCode maps an error returned by Execute to a process exit code.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	// Errors not produced by our commands come from cobra's own argument and
	// flag parsing.
	return ExitUsage
}
