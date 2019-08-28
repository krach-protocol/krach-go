package krach

// Logger is an interface to represent structured logging in krach and to enable usage of different logging backends
type Logger interface {
	WithError(err error) Logger
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger

	Error(args interface{})
	Debug(args interface{})
	Info(args interface{})
	Fatal(args interface{})
}

type dummyLogger struct{}

func (d dummyLogger) WithError(err error) Logger {
	return d
}

func (d dummyLogger) WithField(key string, value interface{}) Logger {
	return d
}

func (d dummyLogger) WithFields(fields map[string]interface{}) Logger {
	return d
}

func (d dummyLogger) Error(args interface{}) {}
func (d dummyLogger) Debug(args interface{}) {}
func (d dummyLogger) Info(args interface{})  {}
func (d dummyLogger) Fatal(args interface{}) {}
