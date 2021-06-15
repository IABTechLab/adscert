package logger

import (
	"log"
)

// Logger interface for standard log library.
type Logger interface {
	Debugf(format string, args ...interface{})

	Infof(format string, args ...interface{})

	Warningf(format string, args ...interface{})

	Errorf(format string, args ...interface{})

	Fatalf(format string, args ...interface{})

	Panicf(format string, args ...interface{})
}

type standardLogger struct {
}

// returns new looger instance. Default is standard log library.
func NewLogger(logger Logger) Logger {
	if logger != nil {
		return logger
	}
	return &standardLogger{}

}

func (l *standardLogger) Debugf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *standardLogger) Infof(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *standardLogger) Warningf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *standardLogger) Errorf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *standardLogger) Fatalf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *standardLogger) Panicf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
