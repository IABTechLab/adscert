package logger

import (
	"log"
)

func init() {
	// Guard clause: should always be nil.
	if globalLogger == nil {
		// Initialize to a default logger that uses a sensible default. Integrators will
		// overwrite this with a different implementation if desired.
		globalLogger = &StandardGolangLogger{VerbosityLevel: INFO}
	}
}

const (
	DEBUG Verbosity = iota - 1
	INFO
	WARNING
	ERROR
	FATAL
	PANIC
)

type Verbosity int

type StandardGolangLogger struct {
	VerbosityLevel Verbosity
}

func (l *StandardGolangLogger) Debugf(format string, args ...interface{}) {
	// Work around standard logger lack of verbosity levels
	if l.VerbosityLevel <= DEBUG {
		log.Printf(format, args...)
	}
}

func (l *StandardGolangLogger) Infof(format string, args ...interface{}) {
	// Work around standard logger lack of verbosity levels
	if l.VerbosityLevel <= INFO {
		log.Printf(format, args...)
	}
}

func (l *StandardGolangLogger) Info(format string) {
	// Work around standard logger lack of verbosity levels
	if l.VerbosityLevel <= INFO {
		log.Print(format)
	}
}

func (l *StandardGolangLogger) Warningf(format string, args ...interface{}) {
	// Work around standard logger lack of verbosity levels
	if l.VerbosityLevel <= WARNING {
		log.Printf(format, args...)
	}
}

func (l *StandardGolangLogger) Errorf(format string, args ...interface{}) {
	// Work around standard logger lack of verbosity levels
	if l.VerbosityLevel <= ERROR {
		log.Printf(format, args...)
	}
}

func (l *StandardGolangLogger) Fatalf(format string, args ...interface{}) {
	// Work around standard logger lack of verbosity levels
	if l.VerbosityLevel <= FATAL {
		log.Printf(format, args...)
	}
}

func (l *StandardGolangLogger) Panicf(format string, args ...interface{}) {
	// Work around standard logger lack of verbosity levels
	if l.VerbosityLevel <= PANIC {
		log.Printf(format, args...)
	}
}
