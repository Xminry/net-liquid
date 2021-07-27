/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logger

import (
	"testing"
)

func TestLogPrinter(t *testing.T) {
	logger := NewLogPrinter("TEST")
	logger.Info("1", 2)
	logger.Infof("%s %d", "1", 2)
	logger.Debug("1", 2)
	logger.Debugf("%s %d", "1", 2)
	logger.Error("1", 2)
	logger.Errorf("%s %d", "1", 2)
	logger.Warn("1", 2)
	logger.Warnf("%s %d", "1", 2)

	logger2 := NewLogPrinter("")
	logger2.Info("1", 2)
	logger2.Infof("%s %d", "1", 2)
	logger2.Debug("1", 2)
	logger2.Debugf("%s %d", "1", 2)
	logger2.Error("1", 2)
	logger2.Errorf("%s %d", "1", 2)
	logger2.Warn("1", 2)
	logger2.Warnf("%s %d", "1", 2)
}
