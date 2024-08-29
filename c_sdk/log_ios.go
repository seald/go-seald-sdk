//go:build ios

package main

/*
#include <stdlib.h>
#include <os/log.h>

os_log_t create_log_object() {
    return os_log_create("SealdSdk", "");
}

static void log_info(const os_log_t log_object, const char *message) {
    os_log(log_object, "%{public}s", message);
}
*/
import "C"

import (
	"io"
	"unsafe"
)

var logObject C.os_log_t = C.create_log_object()

type iosLogWriter struct{}

func (a iosLogWriter) Write(p []byte) (n int, err error) {
	message := C.CString(string(p))
	defer C.free(unsafe.Pointer(message))

	C.log_info(logObject, message)
	return len(p), nil
}

// TODO: this does not show logs on flutter console (but logs show OK in XCode console)
// similar (but not exactly) to https://github.com/flutter/flutter/issues/42410 & https://github.com/flutter/flutter/issues/41133

var logWriter io.Writer = iosLogWriter{}

func init() {
}
