package transport

import (
	"errors"
	"fmt"
)

type PhaseError struct {
	Phase string
	Err   error
}

func (e *PhaseError) Error() string {
	return fmt.Sprintf("%s: %v", e.Phase, e.Err)
}

func (e *PhaseError) Unwrap() error {
	return e.Err
}

func phaseError(phase string, err error) error {
	if err == nil {
		return nil
	}
	return &PhaseError{Phase: phase, Err: err}
}

func ErrorPhase(err error) string {
	var phased *PhaseError
	if errors.As(err, &phased) && phased.Phase != "" {
		return phased.Phase
	}
	return "connect"
}
