package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

// Logger wraps stdlib log with levelled helpers.
type Logger struct {
	info  *log.Logger
	warn  *log.Logger
	err   *log.Logger
}

// New creates a Logger. If logFile is empty, output goes to stdout.
func New(logFile string) *Logger {
	var w io.Writer = os.Stdout
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("cannot open log file %s: %v", logFile, err)
		}
		w = f
	}
	flags := log.Ldate | log.Ltime | log.Lmicroseconds
	return &Logger{
		info: log.New(w, "INFO  ", flags),
		warn: log.New(w, "WARN  ", flags),
		err:  log.New(w, "ERROR ", flags),
	}
}

func (l *Logger) Info(msg string)                        { l.info.Println(msg) }
func (l *Logger) Infof(f string, v ...interface{})       { l.info.Println(fmt.Sprintf(f, v...)) }
func (l *Logger) Warn(msg string)                        { l.warn.Println(msg) }
func (l *Logger) Warnf(f string, v ...interface{})       { l.warn.Println(fmt.Sprintf(f, v...)) }
func (l *Logger) Error(msg string)                       { l.err.Println(msg) }
func (l *Logger) Errorf(f string, v ...interface{})      { l.err.Println(fmt.Sprintf(f, v...)) }
func (l *Logger) Fatalf(f string, v ...interface{})      { l.err.Fatalf(f, v...) }
