/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logger

import (
	api "chainmaker.org/chainmaker/protocol"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	levelDebug Level = "DEBUG"
	levelError Level = "ERROR"
	levelInfo  Level = "INFO"
	levelWarn  Level = "WARN"
	levelFatal Level = "FATAL"
	levelPanic Level = "PANIC"

	lnTemplate      = "%s [%s] %s %s"
	lnLabelTemplate = "%s [%s] [%s] %s %s"

	timeFormat = "2006-01-02 15:04:05.000"
)

type Level string

var _ api.Logger = (*LogPrinter)(nil)

type LogPrinter struct {
	Label string
}

func NewLogPrinter(label string) *LogPrinter {
	return &LogPrinter{
		Label: label,
	}
}

func (l *LogPrinter) location() string {
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		return "<unknown>"
	}
	dir, fileName := filepath.Split(file)
	dir = filepath.Base(dir)
	strBuilder := strings.Builder{}
	strBuilder.WriteString(dir)
	strBuilder.WriteString("/")
	strBuilder.WriteString(fileName)
	strBuilder.WriteString(":")
	strBuilder.WriteString(strconv.Itoa(line))
	return strBuilder.String()
}

func (l *LogPrinter) createContent(args ...interface{}) string {
	if len(args) == 0 {
		return ""
	}
	builder := strings.Builder{}
	for i := range args {
		builder.WriteString(fmt.Sprintf("%v ", args[i]))
	}
	return builder.String()
}

func (l *LogPrinter) println(level Level, args ...interface{}) {
	time := time.Now().Format(timeFormat)
	content := l.createContent(args...)
	if l.Label == "" {
		fmt.Println(fmt.Sprintf(lnTemplate, time, level, l.location(), content))
	} else {
		fmt.Println(fmt.Sprintf(lnLabelTemplate, time, level, l.Label, l.location(), content))
	}
	if level == levelPanic || level == levelFatal {
		panic(content)
	}
}

func (l *LogPrinter) printf(level Level, format string, args ...interface{}) {
	time := time.Now().Format(timeFormat)
	content := fmt.Sprintf(format, args...)
	if l.Label == "" {
		fmt.Println(fmt.Sprintf(lnTemplate, time, level, l.location(), content))
	} else {
		fmt.Println(fmt.Sprintf(lnLabelTemplate, time, level, l.Label, l.location(), content))
	}
	if level == levelPanic || level == levelFatal {
		panic(content)
	}
}

func (l *LogPrinter) Debug(args ...interface{}) {
	l.println(levelDebug, args...)
}

func (l *LogPrinter) Debugf(format string, args ...interface{}) {
	l.printf(levelDebug, format, args...)
}

func (l *LogPrinter) Error(args ...interface{}) {
	l.println(levelError, args...)
}

func (l *LogPrinter) Errorf(format string, args ...interface{}) {
	l.printf(levelError, format, args...)
}

func (l *LogPrinter) Info(args ...interface{}) {
	l.println(levelInfo, args...)
}

func (l *LogPrinter) Infof(format string, args ...interface{}) {
	l.printf(levelInfo, format, args...)
}

func (l *LogPrinter) Panic(args ...interface{}) {
	l.println(levelPanic, args...)
}

func (l *LogPrinter) Panicf(format string, args ...interface{}) {
	l.printf(levelPanic, format, args...)
}

func (l *LogPrinter) Warn(args ...interface{}) {
	l.println(levelWarn, args...)
}

func (l *LogPrinter) Warnf(format string, args ...interface{}) {
	l.printf(levelWarn, format, args...)
}

func (l *LogPrinter) Debugw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) Errorw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) Fatal(args ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) Fatalf(format string, args ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) Fatalw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) Infow(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) Panicw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) Warnw(msg string, keysAndValues ...interface{}) {
	panic("implement me")
}

func (l *LogPrinter) DebugDynamic(getStr func() string) {
	panic("implement me")
}

func (l *LogPrinter) InfoDynamic(getStr func() string) {
	panic("implement me")
}
