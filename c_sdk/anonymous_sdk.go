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

// SDK

func anonymousSdkToGo(cASdk *C.SealdAnonymousSdk) *anonymous_sdk.AnonymousSDK {
	return (*anonymous_sdk.AnonymousSDK)(unsafe.Pointer(cASdk))
}

var sealdAnonymousSdkRefMap = sync.Map{}

//export SealdAnonymousSdk_CreateAnonymousSDK
func SealdAnonymousSdk_CreateAnonymousSDK(options *C.SealdAnonymousInitializeOptions, result **C.SealdAnonymousSdk) {
	aSdkOpts := anonymousInitializeOptionsToGo(options)

	aSdk := anonymous_sdk.CreateAnonymousSDK(aSdkOpts)
	sealdAnonymousSdkRefMap.Store(uintptr(unsafe.Pointer(aSdk)), aSdk)
	*result = (*C.SealdAnonymousSdk)(unsafe.Pointer(aSdk))
}

//export SealdAnonymousSdk_Close
func SealdAnonymousSdk_Close(sealdAnonymousSdk *C.SealdAnonymousSdk) {
	sealdAnonymousSdkRefMap.Delete(uintptr(unsafe.Pointer(sealdAnonymousSdk)))
}

//export SealdAnonymousSdk_CreateAnonymousEncryptionSession
func SealdAnonymousSdk_CreateAnonymousEncryptionSession(sealdAnonymousSdk *C.SealdAnonymousSdk, encryptionToken *C.char, getKeysToken *C.char, recipients *C.SealdStringArray, tmrRecipients *C.SealdAnonymousTmrRecipientsArray, result **C.SealdAnonymousEncryptionSession, err_ **C.SealdError) C.int {
	goRecipients := &anonymous_sdk.Recipients{
		SealdIds:      stringArrayToGo(recipients).getSlice(),
		TMRRecipients: anonymousTmrRecipientsArrayToGo(tmrRecipients).getSlice(),
	}
	aes, err := anonymousSdkToGo(sealdAnonymousSdk).CreateAnonymousEncryptionSession(
		C.GoString(encryptionToken),
		C.GoString(getKeysToken),
		goRecipients,
	)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goAnonymousEncryptionSessionToC(aes)
	return C.int(0)
}

//export SealdAnonymousSdk_DeserializeAnonymousEncryptionSession
func SealdAnonymousSdk_DeserializeAnonymousEncryptionSession(sealdAnonymousSdk *C.SealdAnonymousSdk, serializedSession *C.char, result **C.SealdAnonymousEncryptionSession, err_ **C.SealdError) C.int {
	aes, err := anonymousSdkToGo(sealdAnonymousSdk).DeserializeAnonymousEncryptionSession(C.GoString(serializedSession))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goAnonymousEncryptionSessionToC(aes)
	return C.int(0)
}
