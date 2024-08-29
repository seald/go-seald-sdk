//go:build android

package main

/*
#include <stdlib.h>
#include <android/log.h>
#cgo LDFLAGS: -llog

static void log_info(const char *message) {
__android_log_print(ANDROID_LOG_INFO, "SealdSdk", "%s", message);
}
*/
import "C"

import (
	"io"
	"log"
	"unsafe"
)

type androidLogWriter struct{}

func (a androidLogWriter) Write(p []byte) (n int, err error) {
	cstr := C.CString(string(p))
	defer C.free(unsafe.Pointer(cstr))
	C.log_info(cstr)
	return len(p), nil
}

var logWriter io.Writer = androidLogWriter{}

func init() {
	log.SetOutput(logWriter)
}
