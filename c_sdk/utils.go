package main

/*
#include <stdlib.h>
#include "./seald_sdk.h"
*/
import "C"
import (
	"encoding/base64"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/sdk"
	"github.com/ztrue/tracerr"
	"unsafe"
)

// SealdUtils

//export SealdUtils_ParseSessionIdFromFile
func SealdUtils_ParseSessionIdFromFile(encryptedFilePath *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := sdk.ParseSessionIdFromFile(C.GoString(encryptedFilePath))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdUtils_ParseSessionIdFromBytes
func SealdUtils_ParseSessionIdFromBytes(fileBytes *C.uchar, fileBytesLen C.int, result **C.char, err_ **C.SealdError) C.int {
	fileBytesSlice := C.GoBytes(unsafe.Pointer(fileBytes), fileBytesLen)
	res, err := sdk.ParseSessionIdFromBytes(fileBytesSlice)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdUtils_ParseSessionIdFromMessage
func SealdUtils_ParseSessionIdFromMessage(message *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := sdk.ParseSessionIdFromMessage(C.GoString(message))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdUtils_PKCS1DERtoPKCS8
func SealdUtils_PKCS1DERtoPKCS8(pkcs1DerRsaKeyB64 *C.char, result **C.char, err_ **C.SealdError) C.int {
	pkcs1DerRsaKey, err := base64.StdEncoding.DecodeString(C.GoString(pkcs1DerRsaKeyB64))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	decodedKey, err := asymkey.PrivateKeyDecodePKCS1DER(pkcs1DerRsaKey)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(decodedKey.ToB64())
	return C.int(0)
}

//export SealdUtils_GeneratePrivateKey
func SealdUtils_GeneratePrivateKey(size C.int, result **C.char, err_ **C.SealdError) C.int {
	size_ := int(size)
	if size_ == 0 {
		size_ = 4096
	}
	key, err := asymkey.Generate(size_)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(key.ToB64())
	return C.int(0)
}
