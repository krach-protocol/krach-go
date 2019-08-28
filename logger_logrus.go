//+build !without_logrus

package krach

import (
	"github.com/sirupsen/logrus"
)

type logrusLogger struct {
	logg logrus.FieldLogger
}

func (l *logrusLogger) WithError(err error) Logger {
	l.logg = l.logg.WithError(err)
	return l
}

func (l *logrusLogger) WithField(key string, value interface{}) Logger {
	l.logg = l.logg.WithField(key, value)
	return l
}

func (l *logrusLogger) WithFields(fields map[string]interface{}) Logger {
	l.logg = l.logg.WithFields(logrus.Fields(fields))
	return l
}

func (l *logrusLogger) Error(args interface{}) {
	l.logg.Error(args)
}

func (l *logrusLogger) Debug(args interface{}) {
	l.logg.Debug(args)
}
func (l *logrusLogger) Info(args interface{}) {
	l.logg.Info(args)
}

func (l *logrusLogger) Fatal(args interface{}) {
	l.logg.Fatal(args)
}

func LogrusLogger(logg logrus.FieldLogger) Logger {
	return &logrusLogger{logg}
}
