// Package main not actually the main package. It is an internal wrapper, to help make the seald SDK compatible with C
// (which requires the package to be called "main"). This is not meant to be used by end-users of the Seald SDK.
package main

/*
#include <stdlib.h>
#include "./seald_sdk.h"
*/
import "C"
import (
	"github.com/rs/zerolog"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/common_models"
	"go-seald-sdk/ssks_password"
	"go-seald-sdk/ssks_tmr"
	"go-seald-sdk/utils"
	"sync"
	"unsafe"
)

// Helper SealdSsksTMRPluginInitializeOptions

func ssksTMRPluginInitializeOptionsToGo(cOpts *C.SealdSsksTMRPluginInitializeOptions) *ssks_tmr.PluginTMRInitializeOptions {
	return &ssks_tmr.PluginTMRInitializeOptions{
		SsksURL:      C.GoString(cOpts.SsksURL),
		AppId:        C.GoString(cOpts.AppId),
		LogLevel:     zerolog.Level(int8(cOpts.LogLevel)),
		LogNoColor:   int(cOpts.LogNoColor) != 0,
		InstanceName: C.GoString(cOpts.InstanceName),
		Platform:     C.GoString(cOpts.Platform),
		LogWriter:    logWriter,
	}
}

// SSKS SealdSsksTMRPluginSaveIdentityResponse

//export SealdSsksTMRPluginSaveIdentityResponse_Free
func SealdSsksTMRPluginSaveIdentityResponse_Free(resp *C.SealdSsksTMRPluginSaveIdentityResponse) {
	if resp == nil {
		return
	}
	C.free(unsafe.Pointer(resp.SsksId))
	C.free(unsafe.Pointer(resp.AuthenticatedSessionId))
	C.free(unsafe.Pointer(resp))
}

// SSKS SealdSsksTMRPluginRetrieveIdentityResponse

//export SealdSsksTMRPluginRetrieveIdentityResponse_Free
func SealdSsksTMRPluginRetrieveIdentityResponse_Free(resp *C.SealdSsksTMRPluginRetrieveIdentityResponse) {
	if resp == nil {
		return
	}
	C.free(unsafe.Pointer(resp.Identity))
	C.free(unsafe.Pointer(resp.AuthenticatedSessionId))
	C.free(unsafe.Pointer(resp))
}

// SSKS SealdSsksTMRPluginGetFactorTokenResponse

//export SealdSsksTMRPluginGetFactorTokenResponse_Free
func SealdSsksTMRPluginGetFactorTokenResponse_Free(resp *C.SealdSsksTMRPluginGetFactorTokenResponse) {
	if resp == nil {
		return
	}
	C.free(unsafe.Pointer(resp.Token))
	C.free(unsafe.Pointer(resp.AuthenticatedSessionId))
	C.free(unsafe.Pointer(resp))
}

func SealdSsksTMRPluginGetFactorTokenResponseFromGo(goResp *ssks_tmr.GetFactorTokenResponse) *C.SealdSsksTMRPluginGetFactorTokenResponse {
	res := (*C.SealdSsksTMRPluginGetFactorTokenResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdSsksTMRPluginGetFactorTokenResponse{}))))
	res.AuthenticatedSessionId = C.CString(goResp.AuthenticatedSessionId)
	res.Token = C.CString(goResp.Token)
	return res
}

// SSKS TMR

var SealdSsksTMRPluginRefMap = sync.Map{}

func ssksTMRPluginToGo(cSsksTMRPlugin *C.SealdSsksTMRPlugin) *ssks_tmr.PluginTMR {
	return (*ssks_tmr.PluginTMR)(unsafe.Pointer(cSsksTMRPlugin))
}

//export SealdSsksTMRPlugin_Initialize
func SealdSsksTMRPlugin_Initialize(options *C.SealdSsksTMRPluginInitializeOptions, result **C.SealdSsksTMRPlugin, err_ **C.SealdError) C.int {
	ssksTMRPlugin := ssks_tmr.NewPluginTMR(ssksTMRPluginInitializeOptionsToGo(options))
	*result = (*C.SealdSsksTMRPlugin)(unsafe.Pointer(ssksTMRPlugin))
	SealdSsksTMRPluginRefMap.Store(uintptr(unsafe.Pointer(ssksTMRPlugin)), ssksTMRPlugin)
	return C.int(0)
}

//export SealdSsksTMRPlugin_Free
func SealdSsksTMRPlugin_Free(tmrPlugin *C.SealdSsksTMRPlugin) {
	SealdSsksTMRPluginRefMap.Delete(uintptr(unsafe.Pointer(tmrPlugin)))
}

//export SealdSsksTMRPlugin_SaveIdentity
func SealdSsksTMRPlugin_SaveIdentity(tmrPlugin *C.SealdSsksTMRPlugin, sessionId *C.char, authFactorType *C.char, authFactorValue *C.char, rawTMRSymKey *C.uchar, rawTMRSymKeyLen C.int, identity *C.uchar, identityLen C.int, challenge *C.char, result **C.SealdSsksTMRPluginSaveIdentityResponse, err_ **C.SealdError) C.int {
	identityBytes := C.GoBytes(unsafe.Pointer(identity), identityLen)
	rawTMRSymKeyBytes := C.GoBytes(unsafe.Pointer(rawTMRSymKey), rawTMRSymKeyLen)
	authFactor := &common_models.AuthFactor{
		Type:  C.GoString(authFactorType),
		Value: C.GoString(authFactorValue),
	}
	goResp, err := ssksTMRPluginToGo(tmrPlugin).SaveIdentity(C.GoString(sessionId), authFactor, C.GoString(challenge), rawTMRSymKeyBytes, identityBytes)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	res := (*C.SealdSsksTMRPluginSaveIdentityResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdSsksTMRPluginSaveIdentityResponse{}))))

	res.SsksId = C.CString(goResp.SsksId)
	res.AuthenticatedSessionId = utils.Ternary(goResp.AuthenticatedSessionId != "", C.CString(goResp.AuthenticatedSessionId), nil)

	*result = res
	return C.int(0)
}

//export SealdSsksTMRPlugin_RetrieveIdentity
func SealdSsksTMRPlugin_RetrieveIdentity(tmrPlugin *C.SealdSsksTMRPlugin, sessionId *C.char, authFactorType *C.char, authFactorValue *C.char, rawTMRSymKey *C.uchar, rawTMRSymKeyLen C.int, challenge *C.char, result **C.SealdSsksTMRPluginRetrieveIdentityResponse, err_ **C.SealdError) C.int {
	rawTMRSymKeyBytes := C.GoBytes(unsafe.Pointer(rawTMRSymKey), rawTMRSymKeyLen)
	authFactor := &common_models.AuthFactor{
		Type:  C.GoString(authFactorType),
		Value: C.GoString(authFactorValue),
	}
	goResp, err := ssksTMRPluginToGo(tmrPlugin).RetrieveIdentity(C.GoString(sessionId), authFactor, C.GoString(challenge), rawTMRSymKeyBytes)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	res := (*C.SealdSsksTMRPluginRetrieveIdentityResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdSsksTMRPluginRetrieveIdentityResponse{}))))

	res.Identity = (*C.uchar)(C.CBytes(goResp.Identity))
	res.IdentityLen = C.int(len(goResp.Identity))
	res.AuthenticatedSessionId = C.CString(goResp.AuthenticatedSessionId)
	if goResp.ShouldRenewKey {
		res.ShouldRenewKey = 1
	} else {
		res.ShouldRenewKey = 0
	}

	*result = res
	return C.int(0)
}

//export SealdSsksTMRPlugin_GetFactorToken
func SealdSsksTMRPlugin_GetFactorToken(tmrPlugin *C.SealdSsksTMRPlugin, sessionId *C.char, authFactorType *C.char, authFactorValue *C.char, challenge *C.char, result **C.SealdSsksTMRPluginGetFactorTokenResponse, err_ **C.SealdError) C.int {
	authFactor := &common_models.AuthFactor{
		Type:  C.GoString(authFactorType),
		Value: C.GoString(authFactorValue),
	}
	goResp, err := ssksTMRPluginToGo(tmrPlugin).GetFactorToken(C.GoString(sessionId), authFactor, C.GoString(challenge))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = SealdSsksTMRPluginGetFactorTokenResponseFromGo(goResp)
	return C.int(0)
}

// Helper SealdSsksPasswordPluginInitializeOptions

func ssksPasswordPluginInitializeOptionsToGo(cOpts *C.SealdSsksPasswordPluginInitializeOptions) *ssks_password.PluginPasswordInitializeOptions {
	return &ssks_password.PluginPasswordInitializeOptions{
		SsksURL:      C.GoString(cOpts.SsksURL),
		AppId:        C.GoString(cOpts.AppId),
		LogLevel:     zerolog.Level(int8(cOpts.LogLevel)),
		LogNoColor:   int(cOpts.LogNoColor) != 0,
		InstanceName: C.GoString(cOpts.InstanceName),
		Platform:     C.GoString(cOpts.Platform),
		LogWriter:    logWriter,
	}
}

// SSKS Password

var SealdSsksPasswordPluginRefMap = sync.Map{}

func ssksPasswordPluginToGo(cSsksPasswordPlugin *C.SealdSsksPasswordPlugin) *ssks_password.PluginPassword {
	return (*ssks_password.PluginPassword)(unsafe.Pointer(cSsksPasswordPlugin))
}

//export SealdSsksPasswordPlugin_Initialize
func SealdSsksPasswordPlugin_Initialize(options *C.SealdSsksPasswordPluginInitializeOptions, result **C.SealdSsksPasswordPlugin, err_ **C.SealdError) C.int {
	ssksPasswordPlugin := ssks_password.NewPluginPassword(ssksPasswordPluginInitializeOptionsToGo(options))
	*result = (*C.SealdSsksPasswordPlugin)(unsafe.Pointer(ssksPasswordPlugin))
	SealdSsksPasswordPluginRefMap.Store(uintptr(unsafe.Pointer(ssksPasswordPlugin)), ssksPasswordPlugin)
	return C.int(0)
}

//export SealdSsksPasswordPlugin_Free
func SealdSsksPasswordPlugin_Free(passwordPlugin *C.SealdSsksPasswordPlugin) {
	SealdSsksPasswordPluginRefMap.Delete(uintptr(unsafe.Pointer(passwordPlugin)))
}

//export SealdSsksPasswordPlugin_SaveIdentityFromPassword
func SealdSsksPasswordPlugin_SaveIdentityFromPassword(passwordPlugin *C.SealdSsksPasswordPlugin, userId *C.char, password *C.char, identity *C.uchar, identityLen C.int, result **C.char, err_ **C.SealdError) C.int {
	identityBytes := C.GoBytes(unsafe.Pointer(identity), identityLen)
	res, err := ssksPasswordPluginToGo(passwordPlugin).SaveIdentityFromPassword(C.GoString(userId), C.GoString(password), identityBytes)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdSsksPasswordPlugin_SaveIdentityFromRawKeys
func SealdSsksPasswordPlugin_SaveIdentityFromRawKeys(passwordPlugin *C.SealdSsksPasswordPlugin, userId *C.char, rawStorageKey *C.char, rawEncryptionKey *C.uchar, rawEncryptionKeyLen C.int, identity *C.uchar, identityLen C.int, result **C.char, err_ **C.SealdError) C.int {
	identityBytes := C.GoBytes(unsafe.Pointer(identity), identityLen)
	rawEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(rawEncryptionKey), rawEncryptionKeyLen)
	res, err := ssksPasswordPluginToGo(passwordPlugin).SaveIdentityFromRawKeys(C.GoString(userId), C.GoString(rawStorageKey), rawEncryptionKeyBytes, identityBytes)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdSsksPasswordPlugin_RetrieveIdentityFromPassword
func SealdSsksPasswordPlugin_RetrieveIdentityFromPassword(passwordPlugin *C.SealdSsksPasswordPlugin, userId *C.char, password *C.char, retrievedIdentity **C.uchar, retrievedIdentityLen *C.int, err_ **C.SealdError) C.int {
	retrieveData, err := ssksPasswordPluginToGo(passwordPlugin).RetrieveIdentityFromPassword(C.GoString(userId), C.GoString(password))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*retrievedIdentity = (*C.uchar)(C.CBytes(retrieveData))
	*retrievedIdentityLen = C.int(len(retrieveData))
	return C.int(0)
}

//export SealdSsksPasswordPlugin_RetrieveIdentityFromRawKeys
func SealdSsksPasswordPlugin_RetrieveIdentityFromRawKeys(passwordPlugin *C.SealdSsksPasswordPlugin, userId *C.char, rawStorageKey *C.char, rawEncryptionKey *C.uchar, rawEncryptionKeyLen C.int, retrievedIdentity **C.uchar, retrievedIdentityLen *C.int, err_ **C.SealdError) C.int {
	rawEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(rawEncryptionKey), rawEncryptionKeyLen)
	retrieveData, err := ssksPasswordPluginToGo(passwordPlugin).RetrieveIdentityFromRawKeys(C.GoString(userId), C.GoString(rawStorageKey), rawEncryptionKeyBytes)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*retrievedIdentity = (*C.uchar)(C.CBytes(retrieveData))
	*retrievedIdentityLen = C.int(len(retrieveData))
	return C.int(0)
}

//export SealdSsksPasswordPlugin_ChangeIdentityPassword
func SealdSsksPasswordPlugin_ChangeIdentityPassword(passwordPlugin *C.SealdSsksPasswordPlugin, userId *C.char, currentPassword *C.char, newPassword *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := ssksPasswordPluginToGo(passwordPlugin).ChangeIdentityPassword(C.GoString(userId), C.GoString(currentPassword), C.GoString(newPassword))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}
