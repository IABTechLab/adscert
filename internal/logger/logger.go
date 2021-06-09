package logger

import (
	"fmt"
	"log"
	"os"
)

type LogLevel int

const (
	DEBUG LogLevel = iota - 1
	INFO
	NOTICE
	WARNING
	ERR
	ALERT
	FATAL
	OFF LogLevel = 999
)

type genericLogger interface {
	Printf(format string, v ...interface{})
}

type logger struct {
	level  LogLevel
	Logger genericLogger
}

var Logger = initLogger()

func initLogger() *logger {
	return &logger{
		level:  OFF,
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (lgr *logger) SetLevel(level LogLevel) {
	lgr.level = level
}

func (lgr *logger) SetLogger(loggerInstance genericLogger) {
	lgr.Logger = loggerInstance
}

func (lgr *logger) Log(level LogLevel, format string, v ...interface{}) {
	switch level {
	case DEBUG:
		lgr.Debug(format, v...)
	case INFO:
		lgr.Info(format, v...)
	case WARNING:
		lgr.Warning(format, v...)
	case ERR:
		lgr.Error(format, v...)
	case ALERT:
		lgr.Alert(format, v...)
	case FATAL:
		lgr.Fatal(format, v...)
	case OFF:
	}
}

// Debug logs a message if log level allows to do so.
func (lgr *logger) Debug(format string, v ...interface{}) {
	if lgr.level <= DEBUG {
		if l, ok := lgr.Logger.(*log.Logger); ok {
			l.Output(2, fmt.Sprintf(format, v...))
		} else {
			lgr.Logger.Printf(format, v...)
		}
	}
}

// Info logs a message if log level allows to do so.
func (lgr *logger) Info(format string, v ...interface{}) {
	if lgr.level <= INFO {
		if l, ok := lgr.Logger.(*log.Logger); ok {
			l.Output(2, fmt.Sprintf(format, v...))
		} else {
			lgr.Logger.Printf(format, v...)
		}
	}
}

// Warning logs a message if log level allows to do so.
func (lgr *logger) Warning(format string, v ...interface{}) {
	if lgr.level <= WARNING {
		if l, ok := lgr.Logger.(*log.Logger); ok {
			l.Output(2, fmt.Sprintf(format, v...))
		} else {
			lgr.Logger.Printf(format, v...)
		}
	}
}

// Error logs a message if log level allows to do so.
func (lgr *logger) Error(format string, v ...interface{}) {
	if lgr.level <= ERR {
		if l, ok := lgr.Logger.(*log.Logger); ok {
			l.Output(2, fmt.Sprintf(format, v...))
		} else {
			lgr.Logger.Printf(format, v...)
		}
	}
}

// Alert logs a message if log level allows to do so.
func (lgr *logger) Alert(format string, v ...interface{}) {
	if lgr.level <= ALERT {
		if l, ok := lgr.Logger.(*log.Logger); ok {
			l.Output(2, fmt.Sprintf(format, v...))
		} else {
			lgr.Logger.Printf(format, v...)
		}
	}
}

// Fatal logs a message if log level allows to do so.
func (lgr *logger) Fatal(format string, v ...interface{}) {
	if lgr.level <= FATAL {
		if l, ok := lgr.Logger.(*log.Logger); ok {
			l.Output(2, fmt.Sprintf(format, v...))
		} else {
			lgr.Logger.Printf(format, v...)
		}
	}
}
