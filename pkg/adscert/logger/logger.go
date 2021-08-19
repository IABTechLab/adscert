package logger

var globalLogger Logger

// SetLoggerImpl lets you override the Logger implementation.  Calls are not thread-safe, so set this first thing.
func SetLoggerImpl(newLogger Logger) {
	globalLogger = newLogger
}

type Logger interface {
	Debugf(format string, args ...interface{})

	Infof(format string, args ...interface{})

	Info(format string)

	Warningf(format string, args ...interface{})

	Errorf(format string, args ...interface{})

	Fatalf(format string, args ...interface{})

	Panicf(format string, args ...interface{})
}

func Debugf(format string, args ...interface{}) {
	globalLogger.Debugf(format, args...)
}

func Infof(format string, args ...interface{}) {
	globalLogger.Infof(format, args...)
}

func Info(format string) {
	globalLogger.Info(format)
}

func Warningf(format string, args ...interface{}) {
	globalLogger.Warningf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	globalLogger.Errorf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	globalLogger.Fatalf(format, args...)
}

func Panicf(format string, args ...interface{}) {
	globalLogger.Panicf(format, args...)
}
