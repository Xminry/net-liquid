package util

import (
	"fmt"
	"net"
	"strings"
)

func ParseErrsToStr(errs []error) string {
	tmp := "[%s]"
	res := ""
	for i := range errs {
		res += fmt.Sprintf(tmp, errs[i].Error())
	}
	return res
}

// IsNetError parse a err to a net.Error if it is a implementation of net.Error interface.
func IsNetError(err error) (net.Error, bool) {
	e, ok := err.(net.Error)
	if ok {
		return e, ok
	}
	return nil, false
}

// IsNetErrorTemporary return the value of err.Temporary() if err is a net.Error.
// If err is not a net.Error, return false.
func IsNetErrorTemporary(err error) bool {
	e, ok := IsNetError(err)
	if ok {
		return e.Temporary()
	}
	return false
}

// IsNetErrorTimeout return the value of err.Timeout() if err is a net.Error.
// If err is not a net.Error, return false.
func IsNetErrorTimeout(err error) bool {
	e, ok := IsNetError(err)
	if ok {
		return e.Timeout()
	}
	return false
}

// IsConnClosedError return true if the info of err contains closed strings.
func IsConnClosedError(err error) bool {
	return strings.Contains(err.Error(), "Application error 0x0")
}
