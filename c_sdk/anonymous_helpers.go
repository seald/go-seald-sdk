package main

/*
#include "./seald_sdk.h"
*/
import "C"
import (
	"github.com/rs/zerolog"
	"github.com/seald/go-seald-sdk/anonymous_sdk"
	"github.com/seald/go-seald-sdk/common_models"
	"sync"
	"unsafe"
)

// Helper SealdAnonymousInitializeOptions

func anonymousInitializeOptionsToGo(cOpts *C.SealdAnonymousInitializeOptions) *anonymous_sdk.AnonymousInitializeOptions {
	return &anonymous_sdk.AnonymousInitializeOptions{
		ApiURL:       C.GoString(cOpts.ApiURL),
		AppId:        C.GoString(cOpts.AppId),
		LogLevel:     zerolog.Level(int8(cOpts.LogLevel)),
		LogNoColor:   int(cOpts.LogNoColor) != 0,
		InstanceName: C.GoString(cOpts.InstanceName),
		Platform:     C.GoString(cOpts.Platform),
		LogWriter:    logWriter,
	}
}

// Helper SealdAnonymousTmrRecipientsArray

type SealdAnonymousTmrRecipientsArray struct {
	items []*anonymous_sdk.TMRRecipient
}

func anonymousTmrRecipientsArrayToGo(array *C.SealdAnonymousTmrRecipientsArray) *SealdAnonymousTmrRecipientsArray {
	if array == nil {
		return nil
	}
	return (*SealdAnonymousTmrRecipientsArray)(unsafe.Pointer(array))
}

var sealdAnonymousTmrRecipientsArrayRefMap = sync.Map{}

//export SealdAnonymousTmrRecipientsArray_New
func SealdAnonymousTmrRecipientsArray_New() *C.SealdAnonymousTmrRecipientsArray {
	array := &SealdAnonymousTmrRecipientsArray{}
	sealdAnonymousTmrRecipientsArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdAnonymousTmrRecipientsArray)(unsafe.Pointer(array))
}

//export SealdAnonymousTmrRecipientsArray_Free
func SealdAnonymousTmrRecipientsArray_Free(array *C.SealdAnonymousTmrRecipientsArray) {
	sealdAnonymousTmrRecipientsArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdAnonymousTmrRecipientsArray_Add
func SealdAnonymousTmrRecipientsArray_Add(array *C.SealdAnonymousTmrRecipientsArray, authFactorType *C.char, authFactorValue *C.char, overEncryptionKey *C.uchar, overEncryptionKeyLen C.int) {
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(overEncryptionKey), overEncryptionKeyLen)

	goArray := anonymousTmrRecipientsArrayToGo(array)
	goArray.items = append(goArray.items, &anonymous_sdk.TMRRecipient{
		AuthFactor: &common_models.AuthFactor{
			Type:  C.GoString(authFactorType),
			Value: C.GoString(authFactorValue),
		},
		RawOverEncryptionKey: overEncryptionKeyBytes,
	})
}

//export SealdAnonymousTmrRecipientsArray_Get
func SealdAnonymousTmrRecipientsArray_Get(array *C.SealdAnonymousTmrRecipientsArray, i C.int, authFactorType **C.char, authFactorValue **C.char, overEncryptionKey **C.uchar, overEncryptionKeyLen *C.int, recipientRightRead *C.int, recipientRightForward *C.int, recipientRightRevoke *C.int) {
	goArray := anonymousTmrRecipientsArrayToGo(array)
	tmrR := goArray.items[int(i)]

	*authFactorType = C.CString(tmrR.AuthFactor.Type)
	*authFactorValue = C.CString(tmrR.AuthFactor.Value)

	*overEncryptionKey = (*C.uchar)(C.CBytes(tmrR.RawOverEncryptionKey))
	*overEncryptionKeyLen = C.int(len(tmrR.RawOverEncryptionKey))
}

//export SealdAnonymousTmrRecipientsArray_Size
func SealdAnonymousTmrRecipientsArray_Size(array *C.SealdAnonymousTmrRecipientsArray) C.int {
	goArray := anonymousTmrRecipientsArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdAnonymousTmrRecipientsArray) getSlice() []*anonymous_sdk.TMRRecipient {
	if array == nil {
		return nil
	}
	return array.items
}
