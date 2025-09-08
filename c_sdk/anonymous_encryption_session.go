package main

/*
#include "./seald_sdk.h"
*/
import "C"
import (
	"github.com/seald/go-seald-sdk/anonymous_sdk"
	"github.com/ztrue/tracerr"
	"sync"
	"unsafe"
)

func anonymousEncryptionSessionToGo(aes *C.SealdAnonymousEncryptionSession) *anonymous_sdk.AnonymousEncryptionSession {
	return (*anonymous_sdk.AnonymousEncryptionSession)(unsafe.Pointer(aes))
}

var sealdAnonymousEncryptionSessionRefMap = sync.Map{}

func goAnonymousEncryptionSessionToC(aes *anonymous_sdk.AnonymousEncryptionSession) *C.SealdAnonymousEncryptionSession {
	sealdAnonymousEncryptionSessionRefMap.Store(uintptr(unsafe.Pointer(aes)), aes)
	return (*C.SealdAnonymousEncryptionSession)(unsafe.Pointer(aes))
}

//export SealdAnonymousEncryptionSession_Free
func SealdAnonymousEncryptionSession_Free(aes *C.SealdAnonymousEncryptionSession) {
	sealdAnonymousEncryptionSessionRefMap.Delete(uintptr(unsafe.Pointer(aes)))
}

//export SealdAnonymousEncryptionSession_Id
func SealdAnonymousEncryptionSession_Id(es *C.SealdAnonymousEncryptionSession) *C.char {
	return C.CString(anonymousEncryptionSessionToGo(es).SessionId)
}

//export SealdAnonymousEncryptionSession_EncryptMessage
func SealdAnonymousEncryptionSession_EncryptMessage(es *C.SealdAnonymousEncryptionSession, clearMessage *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := anonymousEncryptionSessionToGo(es).EncryptMessage(C.GoString(clearMessage))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdAnonymousEncryptionSession_DecryptMessage
func SealdAnonymousEncryptionSession_DecryptMessage(es *C.SealdAnonymousEncryptionSession, encryptedMessage *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := anonymousEncryptionSessionToGo(es).DecryptMessage(C.GoString(encryptedMessage))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdAnonymousEncryptionSession_EncryptFile
func SealdAnonymousEncryptionSession_EncryptFile(es *C.SealdAnonymousEncryptionSession, clearFile *C.uchar, clearFileLen C.int, filename *C.char, result **C.uchar, resultLen *C.int, err_ **C.SealdError) C.int {
	clearFileSlice := C.GoBytes(unsafe.Pointer(clearFile), clearFileLen)
	res, err := anonymousEncryptionSessionToGo(es).EncryptFile(clearFileSlice, C.GoString(filename))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = (*C.uchar)(C.CBytes(res))
	*resultLen = C.int(len(res))
	return C.int(0)
}

//export SealdAnonymousEncryptionSession_DecryptFile
func SealdAnonymousEncryptionSession_DecryptFile(es *C.SealdAnonymousEncryptionSession, encryptedFile *C.uchar, encryptedFileLen C.int, result **C.SealdClearFile, err_ **C.SealdError) C.int {
	encryptedFileSlice := C.GoBytes(unsafe.Pointer(encryptedFile), encryptedFileLen)
	res, err := anonymousEncryptionSessionToGo(es).DecryptFile(encryptedFileSlice)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = clearFileFromCommon(res)
	return C.int(0)
}

//export SealdAnonymousEncryptionSession_EncryptFileFromPath
func SealdAnonymousEncryptionSession_EncryptFileFromPath(es *C.SealdAnonymousEncryptionSession, clearFilePath *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := anonymousEncryptionSessionToGo(es).EncryptFileFromPath(C.GoString(clearFilePath))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdAnonymousEncryptionSession_DecryptFileFromPath
func SealdAnonymousEncryptionSession_DecryptFileFromPath(es *C.SealdAnonymousEncryptionSession, encryptedFilePath *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := anonymousEncryptionSessionToGo(es).DecryptFileFromPath(C.GoString(encryptedFilePath))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdAnonymousEncryptionSession_Serialize
func SealdAnonymousEncryptionSession_Serialize(es *C.SealdAnonymousEncryptionSession, result **C.char, err_ **C.SealdError) C.int {
	res, err := anonymousEncryptionSessionToGo(es).Serialize()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = C.CString(res)
	return C.int(0)
}
