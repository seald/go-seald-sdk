package main

/*
#include "./seald_sdk.h"
*/
import "C"
import (
	"github.com/ztrue/tracerr"
	"go-seald-sdk/common_models"
	"go-seald-sdk/sdk"
	"sync"
	"unsafe"
)

// Encryption Session

func encryptionSessionToGo(es *C.SealdEncryptionSession) *sdk.EncryptionSession {
	return (*sdk.EncryptionSession)(unsafe.Pointer(es))
}

var sealdEncryptionSessionRefMap = sync.Map{}

func goEncryptionSessionToC(es *sdk.EncryptionSession) *C.SealdEncryptionSession {
	sealdEncryptionSessionRefMap.Store(uintptr(unsafe.Pointer(es)), es)
	return (*C.SealdEncryptionSession)(unsafe.Pointer(es))
}

//export SealdEncryptionSession_Free
func SealdEncryptionSession_Free(es *C.SealdEncryptionSession) {
	sealdEncryptionSessionRefMap.Delete(uintptr(unsafe.Pointer(es)))
}

//export SealdEncryptionSession_Id
func SealdEncryptionSession_Id(es *C.SealdEncryptionSession) *C.char {
	return C.CString(encryptionSessionToGo(es).Id)
}

//export SealdEncryptionSession_RetrievalDetails
func SealdEncryptionSession_RetrievalDetails(es *C.SealdEncryptionSession) *C.SealdEncryptionSessionRetrievalDetails {
	return retrievalDetailsFromGo(encryptionSessionToGo(es).RetrievalDetails)
}

//export SealdEncryptionSession_AddRecipients
func SealdEncryptionSession_AddRecipients(es *C.SealdEncryptionSession, recipients *C.SealdRecipientsWithRightsArray, result **C.SealdActionStatusArray, err_ **C.SealdError) C.int {
	resp, err := encryptionSessionToGo(es).AddRecipients(recipientsWithRightsArrayToGo(recipients).getSlice())
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = actionStatusArrayFromAddKey(resp)
	return C.int(0)
}

//export SealdEncryptionSession_AddProxySession
func SealdEncryptionSession_AddProxySession(es *C.SealdEncryptionSession, proxySessionId *C.char, readRight C.int, forwardRight C.int, revokeRight C.int, err_ **C.SealdError) C.int {
	err := encryptionSessionToGo(es).AddProxySession(
		C.GoString(proxySessionId),
		&sdk.RecipientRights{
			Read:    readRight == 1,
			Forward: forwardRight == 1,
			Revoke:  revokeRight == 1,
		},
	)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdEncryptionSession_RevokeRecipients
func SealdEncryptionSession_RevokeRecipients(es *C.SealdEncryptionSession, recipientsIds *C.SealdStringArray, proxySessionsIds *C.SealdStringArray, result **C.SealdRevokeResult, err_ **C.SealdError) C.int {
	resp, err := encryptionSessionToGo(es).RevokeRecipients(stringArrayToGo(recipientsIds).getSlice(), stringArrayToGo(proxySessionsIds).getSlice())
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = revokeResultFromGo(resp.UserIds, resp.ProxyMkIds)
	return C.int(0)
}

//export SealdEncryptionSession_RevokeAll
func SealdEncryptionSession_RevokeAll(es *C.SealdEncryptionSession, result **C.SealdRevokeResult, err_ **C.SealdError) C.int {
	resp, err := encryptionSessionToGo(es).RevokeAll()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = revokeResultFromGo(resp.RevokeAll.UserIds, resp.RevokeAll.ProxyMkIds)
	return C.int(0)
}

//export SealdEncryptionSession_RevokeOthers
func SealdEncryptionSession_RevokeOthers(es *C.SealdEncryptionSession, result **C.SealdRevokeResult, err_ **C.SealdError) C.int {
	resp, err := encryptionSessionToGo(es).RevokeOthers()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = revokeResultFromGo(resp.RevokeAll.UserIds, resp.RevokeAll.ProxyMkIds)
	return C.int(0)
}

//export SealdEncryptionSession_EncryptMessage
func SealdEncryptionSession_EncryptMessage(es *C.SealdEncryptionSession, clearMessage *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := encryptionSessionToGo(es).EncryptMessage(C.GoString(clearMessage))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdEncryptionSession_DecryptMessage
func SealdEncryptionSession_DecryptMessage(es *C.SealdEncryptionSession, encryptedMessage *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := encryptionSessionToGo(es).DecryptMessage(C.GoString(encryptedMessage))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdEncryptionSession_EncryptFile
func SealdEncryptionSession_EncryptFile(es *C.SealdEncryptionSession, clearFile *C.uchar, clearFileLen C.int, filename *C.char, result **C.uchar, resultLen *C.int, err_ **C.SealdError) C.int {
	clearFileSlice := C.GoBytes(unsafe.Pointer(clearFile), clearFileLen)
	res, err := encryptionSessionToGo(es).EncryptFile(clearFileSlice, C.GoString(filename))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = (*C.uchar)(C.CBytes(res))
	*resultLen = C.int(len(res))
	return C.int(0)
}

//export SealdEncryptionSession_DecryptFile
func SealdEncryptionSession_DecryptFile(es *C.SealdEncryptionSession, encryptedFile *C.uchar, encryptedFileLen C.int, result **C.SealdClearFile, err_ **C.SealdError) C.int {
	encryptedFileSlice := C.GoBytes(unsafe.Pointer(encryptedFile), encryptedFileLen)
	res, err := encryptionSessionToGo(es).DecryptFile(encryptedFileSlice)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = clearFileFromCommon(res)
	return C.int(0)
}

//export SealdEncryptionSession_EncryptFileFromPath
func SealdEncryptionSession_EncryptFileFromPath(es *C.SealdEncryptionSession, clearFilePath *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := encryptionSessionToGo(es).EncryptFileFromPath(C.GoString(clearFilePath))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdEncryptionSession_DecryptFileFromPath
func SealdEncryptionSession_DecryptFileFromPath(es *C.SealdEncryptionSession, encryptedFilePath *C.char, result **C.char, err_ **C.SealdError) C.int {
	res, err := encryptionSessionToGo(es).DecryptFileFromPath(C.GoString(encryptedFilePath))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = C.CString(res)
	return C.int(0)
}

//export SealdEncryptionSession_AddTmrAccess
func SealdEncryptionSession_AddTmrAccess(es *C.SealdEncryptionSession, authFactorType *C.char, authFactorValue *C.char, overEncryptionKey *C.uchar, overEncryptionKeyLen C.int, readRight C.int, forwardRight C.int, revokeRight C.int, result **C.char, err_ **C.SealdError) C.int {
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(overEncryptionKey), overEncryptionKeyLen)
	recipientRights := &sdk.RecipientRights{
		Read:    readRight == 1,
		Forward: forwardRight == 1,
		Revoke:  revokeRight == 1,
	}
	authFactor := &common_models.AuthFactor{
		Type:  C.GoString(authFactorType),
		Value: C.GoString(authFactorValue),
	}
	recipient := &sdk.TmrRecipientWithRights{AuthFactor: authFactor, Rights: recipientRights, OverEncryptionKey: overEncryptionKeyBytes}
	tmrAccessId, err := encryptionSessionToGo(es).AddTmrAccess(recipient)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = C.CString(tmrAccessId)
	return C.int(0)
}

//export SealdEncryptionSession_AddMultipleTmrAccesses
func SealdEncryptionSession_AddMultipleTmrAccesses(es *C.SealdEncryptionSession, recipients *C.SealdTmrRecipientsWithRightsArray, result **C.SealdActionStatusArray, err_ **C.SealdError) C.int {
	resp, err := encryptionSessionToGo(es).AddMultipleTmrAccesses(tmrRecipientsWithRightsArrayToGo(recipients).getSlice())
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = actionStatusArrayFromAddTmrAccess(resp)
	return C.int(0)
}
