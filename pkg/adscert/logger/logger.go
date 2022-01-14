package logger

var globalLogger Logger

// SetLoggerImpl lets you override the Logger implementation.  Calls are not
// thread-safe, so set this first thing at application start.
func SetLoggerImpl(newLogger Logger) {
	globalLogger = newLogger
}

// Logger provides a general interface for generic logging functionality.
// Implementers who want to utilize a different logging library/strategy can use
// this interface to plug in a different implementation.
type Logger interface {
	// Debugf logs events labeled with DEBUG severity.
	Debugf(format string, args ...interface{})

	// Infof logs events labeled with INFO severity.
	Infof(format string, args ...interface{})

	// Info logs events labeled with INFO severity.
	Info(format string)

	// Warningf logs events labeled with WARNING severity.
	Warningf(format string, args ...interface{})

	// Errorf logs events labeled with ERROR severity.
	Errorf(format string, args ...interface{})

	// Fatalf logs the message and internally will call os.Exit(1).  This log
	// level cannot be overridden by configuration changes.
	Fatalf(format string, args ...interface{})

	// Panicf logs the message and internally will call panic() using the
	// message as an argument.  This log level cannot be overridden by
	// configuration changes.
	Panicf(format string, args ...interface{})
}

// Debugf logs events labeled with DEBUG severity.
func Debugf(format string, args ...interface{}) {
	globalLogger.Debugf(format, args...)
}

// Infof logs events labeled with INFO severity.
func Infof(format string, args ...interface{}) {
	globalLogger.Infof(format, args...)
}

// Info logs events labeled with INFO severity.
func Info(format string) {
	globalLogger.Info(format)
}

// Warningf logs events labeled with WARNING severity.
func Warningf(format string, args ...interface{}) {
	globalLogger.Warningf(format, args...)
}

// Errorf logs events labeled with ERROR severity.
func Errorf(format string, args ...interface{}) {
	globalLogger.Errorf(format, args...)
}

// Fatalf logs the message and internally will call os.Exit(1).  This log
// level cannot be overridden by configuration changes.
func Fatalf(format string, args ...interface{}) {
	globalLogger.Fatalf(format, args...)
}

// Panicf logs the message and internally will call panic() using the
// message as an argument.  This log level cannot be overridden by
// configuration changes.
func Panicf(format string, args ...interface{}) {
	globalLogger.Panicf(format, args...)
}
