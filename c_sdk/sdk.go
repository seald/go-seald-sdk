// Package main not actually the main package. It is an internal wrapper, to help make the seald SDK compatible with C
// (which requires the package to be called "main"). This is not meant to be used by end-users of the Seald SDK.
package main

/*
#include <stdlib.h>
#include "./seald_sdk.h"
*/
import "C"
import (
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"sync"
	"time"
	"unsafe"
)

var (
	ErrorInvalidPregeneratedKey = utils.NewSealdError("C_INVALID_PREGENERATED_KEY", "invalid pregenerated keys : one passed non-nil, one nil")
)

// SDK

func sdkToGo(cSdk *C.SealdSdk) *sdk.State {
	return (*sdk.State)(unsafe.Pointer(cSdk))
}

var sealdSdkRefMap = sync.Map{}

//export SealdSdk_Version
func SealdSdk_Version() *C.char {
	return C.CString(utils.Version)
}

//export SealdSdk_Initialize
func SealdSdk_Initialize(options *C.SealdInitializeOptions, result **C.SealdSdk, err_ **C.SealdError) C.int {
	sdkOpts, err := initializeOptionsToGo(options)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	state, err := sdk.Initialize(sdkOpts)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	sealdSdkRefMap.Store(uintptr(unsafe.Pointer(state)), state)
	*result = (*C.SealdSdk)(unsafe.Pointer(state))
	return C.int(0)
}

//export SealdSdk_Close
func SealdSdk_Close(sealdSdk *C.SealdSdk, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).Close()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	sealdSdkRefMap.Delete(uintptr(unsafe.Pointer(sealdSdk)))
	return C.int(0)
}

// Account

func getPreGeneratedKeys(preGeneratedEncryptionKey *C.char, preGeneratedSigningKey *C.char) (*sdk.PreGeneratedKeys, error) {
	if preGeneratedEncryptionKey == nil && preGeneratedSigningKey == nil { // both null => no pre-generated key
		return nil, nil
	}
	if preGeneratedEncryptionKey == nil || preGeneratedSigningKey == nil { // one null, one not => error
		return nil, tracerr.Wrap(ErrorInvalidPregeneratedKey)
	}
	goPreGeneratedEncryptionKey := C.GoString(preGeneratedEncryptionKey)
	goPreGeneratedSigningKey := C.GoString(preGeneratedSigningKey)
	if len(goPreGeneratedEncryptionKey) == 0 && len(goPreGeneratedSigningKey) == 0 { // both empty string => no pre-generated key
		return nil, nil
	} // no need to test if one empty string one not : asymkey.PrivateKeyFromB64 will return error
	encryptionKey, err := asymkey.PrivateKeyFromB64(goPreGeneratedEncryptionKey)
	if err != nil {
		return nil, err
	}
	signingKey, err := asymkey.PrivateKeyFromB64(goPreGeneratedSigningKey)
	if err != nil {
		return nil, err
	}
	return &sdk.PreGeneratedKeys{EncryptionKey: encryptionKey, SigningKey: signingKey}, nil
}

//export SealdSdk_CreateAccount
func SealdSdk_CreateAccount(sealdSdk *C.SealdSdk, displayName *C.char, deviceName *C.char, signupJwt *C.char, expireAfter C.longlong, preGeneratedEncryptionKey *C.char, preGeneratedSigningKey *C.char, result **C.SealdAccountInfo, err_ **C.SealdError) C.int {
	preGeneratedKeys, err := getPreGeneratedKeys(preGeneratedEncryptionKey, preGeneratedSigningKey)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	accountInfo, err := sdkToGo(sealdSdk).CreateAccount(&sdk.CreateAccountOptions{
		DisplayName:      C.GoString(displayName),
		DeviceName:       C.GoString(deviceName),
		SignupJWT:        C.GoString(signupJwt),
		ExpireAfter:      time.Duration(int64(expireAfter)) * time.Millisecond,
		PreGeneratedKeys: preGeneratedKeys,
	})
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = accountInfoFromCommon(accountInfo)
	return C.int(0)
}

//export SealdSdk_GetCurrentAccountInfo
func SealdSdk_GetCurrentAccountInfo(sealdSdk *C.SealdSdk) *C.SealdAccountInfo {
	accountInfo := sdkToGo(sealdSdk).GetCurrentAccountInfo()
	if accountInfo == nil {
		return nil
	}
	return accountInfoFromCommon(accountInfo)
}

//export SealdSdk_UpdateCurrentDevice
func SealdSdk_UpdateCurrentDevice(sealdSdk *C.SealdSdk, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).UpdateCurrentDevice()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_PrepareRenew
func SealdSdk_PrepareRenew(sealdSdk *C.SealdSdk, preGeneratedEncryptionKey *C.char, preGeneratedSigningKey *C.char, result **C.uchar, resultLen *C.int, err_ **C.SealdError) C.int {
	preGeneratedKeys, err := getPreGeneratedKeys(preGeneratedEncryptionKey, preGeneratedSigningKey)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	preparedRenewalBytes, err := sdkToGo(sealdSdk).PrepareRenew(sdk.PrepareRenewOptions{
		PreGeneratedKeys: preGeneratedKeys,
	})
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = (*C.uchar)(C.CBytes(preparedRenewalBytes))
	*resultLen = C.int(len(preparedRenewalBytes))
	return C.int(0)
}

//export SealdSdk_RenewKeys
func SealdSdk_RenewKeys(sealdSdk *C.SealdSdk, keyExpireAfter C.longlong, preGeneratedEncryptionKey *C.char, preGeneratedSigningKey *C.char, preparedRenewal *C.uchar, preparedRenewalLen C.int, err_ **C.SealdError) C.int {
	preGeneratedKeys, err := getPreGeneratedKeys(preGeneratedEncryptionKey, preGeneratedSigningKey)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	var preparedRenewalBytes []byte
	if preparedRenewal != nil {
		preparedRenewalBytes = C.GoBytes(unsafe.Pointer(preparedRenewal), preparedRenewalLen)
	}

	err = sdkToGo(sealdSdk).RenewKeys(sdk.RenewKeysOptions{
		ExpireAfter:      time.Duration(int64(keyExpireAfter)) * time.Millisecond,
		PreGeneratedKeys: preGeneratedKeys,
		PreparedRenewal:  preparedRenewalBytes,
	})
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_CreateSubIdentity
func SealdSdk_CreateSubIdentity(sealdSdk *C.SealdSdk, deviceName *C.char, expireAfter C.longlong, preGeneratedEncryptionKey *C.char, preGeneratedSigningKey *C.char, result **C.SealdCreateSubIdentityResponse, err_ **C.SealdError) C.int {
	preGeneratedKeys, err := getPreGeneratedKeys(preGeneratedEncryptionKey, preGeneratedSigningKey)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	res, err := sdkToGo(sealdSdk).CreateSubIdentity(&sdk.CreateSubIdentityOptions{
		DeviceName:       C.GoString(deviceName),
		ExpireAfter:      time.Duration(int64(expireAfter)) * time.Millisecond,
		PreGeneratedKeys: preGeneratedKeys,
	})
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = createSubIdentityResponseFromCommon(res)
	return C.int(0)
}

//export SealdSdk_ImportIdentity
func SealdSdk_ImportIdentity(sealdSdk *C.SealdSdk, identity *C.uchar, identityLen C.int, err_ **C.SealdError) C.int {
	identityBytes := C.GoBytes(unsafe.Pointer(identity), identityLen)
	err := sdkToGo(sealdSdk).ImportIdentity(identityBytes)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_ExportIdentity
func SealdSdk_ExportIdentity(sealdSdk *C.SealdSdk, result **C.uchar, resultLen *C.int, err_ **C.SealdError) C.int {
	identityBytes, err := sdkToGo(sealdSdk).ExportIdentity()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = (*C.uchar)(C.CBytes(identityBytes))
	*resultLen = C.int(len(identityBytes))
	return C.int(0)
}

//export SealdSdk_PushJWT
func SealdSdk_PushJWT(sealdSdk *C.SealdSdk, jwt *C.char, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).PushJWT(C.GoString(jwt))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_Heartbeat
func SealdSdk_Heartbeat(sealdSdk *C.SealdSdk, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).Heartbeat()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

// Groups

//export SealdSdk_CreateGroup
func SealdSdk_CreateGroup(sealdSdk *C.SealdSdk, groupName *C.char, members *C.SealdStringArray, admins *C.SealdStringArray, preGeneratedEncryptionKey *C.char, preGeneratedSigningKey *C.char, groupId **C.char, err_ **C.SealdError) C.int {
	preGeneratedKeys, err := getPreGeneratedKeys(preGeneratedEncryptionKey, preGeneratedSigningKey)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	id, err := sdkToGo(sealdSdk).CreateGroup(C.GoString(groupName), stringArrayToGo(members).getSlice(), stringArrayToGo(admins).getSlice(), preGeneratedKeys)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*groupId = C.CString(id)
	return C.int(0)
}

//export SealdSdk_AddGroupMembers
func SealdSdk_AddGroupMembers(sealdSdk *C.SealdSdk, groupId *C.char, membersToAdd *C.SealdStringArray, adminsToSet *C.SealdStringArray, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).AddGroupMembers(C.GoString(groupId), stringArrayToGo(membersToAdd).getSlice(), stringArrayToGo(adminsToSet).getSlice())
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_RemoveGroupMembers
func SealdSdk_RemoveGroupMembers(sealdSdk *C.SealdSdk, groupId *C.char, membersToRemove *C.SealdStringArray, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).RemoveGroupMembers(C.GoString(groupId), stringArrayToGo(membersToRemove).getSlice())
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_RenewGroupKey
func SealdSdk_RenewGroupKey(sealdSdk *C.SealdSdk, groupId *C.char, preGeneratedEncryptionKey *C.char, preGeneratedSigningKey *C.char, err_ **C.SealdError) C.int {
	preGeneratedKeys, err := getPreGeneratedKeys(preGeneratedEncryptionKey, preGeneratedSigningKey)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	err = sdkToGo(sealdSdk).RenewGroupKey(C.GoString(groupId), preGeneratedKeys)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_SetGroupAdmins
func SealdSdk_SetGroupAdmins(sealdSdk *C.SealdSdk, groupId *C.char, addToAdmins *C.SealdStringArray, removeFromAdmins *C.SealdStringArray, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).SetGroupAdmins(C.GoString(groupId), stringArrayToGo(addToAdmins).getSlice(), stringArrayToGo(removeFromAdmins).getSlice())
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	return C.int(0)
}

//export SealdSdk_ShouldRenewGroup
func SealdSdk_ShouldRenewGroup(sealdSdk *C.SealdSdk, groupId *C.char, result *C.int, err_ **C.SealdError) C.int {
	res, err := sdkToGo(sealdSdk).ShouldRenewGroup(C.GoString(groupId))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = boolToCInt(res)
	return C.int(0)
}

//export SealdSdk_CreateGroupTMRTemporaryKey
func SealdSdk_CreateGroupTMRTemporaryKey(sealdSdk *C.SealdSdk, groupId *C.char, authFactorType *C.char, authFactorValue *C.char, isAdmin C.int, rawOverEncryptionKey *C.uchar, rawOverEncryptionKeyLen C.int, result **C.SealdGroupTMRTemporaryKey, err_ **C.SealdError) C.int {
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(rawOverEncryptionKey), rawOverEncryptionKeyLen)
	authFactor := &common_models.AuthFactor{
		Type:  C.GoString(authFactorType),
		Value: C.GoString(authFactorValue),
	}

	nativeGTMRTK, err := sdkToGo(sealdSdk).CreateGroupTMRTemporaryKey(C.GoString(groupId), authFactor, int(isAdmin) != 0, overEncryptionKeyBytes)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = sealdGroupTMRTempKeyFromGo(nativeGTMRTK)
	return C.int(0)
}

//export SealdSdk_ListGroupTMRTemporaryKeys
func SealdSdk_ListGroupTMRTemporaryKeys(sealdSdk *C.SealdSdk, groupId *C.char, page C.int, all C.int, nbPageFound *C.int, keysList **C.SealdGroupTMRTemporaryKeysArray, err_ **C.SealdError) C.int {
	nativeGTMRTK, err := sdkToGo(sealdSdk).ListGroupTMRTemporaryKeys(C.GoString(groupId), int(page), int(all) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*keysList = sliceToSealdGroupTMRTemporaryKeysArray(nativeGTMRTK.Keys)
	*nbPageFound = C.int(nativeGTMRTK.NbPage)
	return C.int(0)
}

//export SealdSdk_DeleteGroupTMRTemporaryKey
func SealdSdk_DeleteGroupTMRTemporaryKey(sealdSdk *C.SealdSdk, groupId *C.char, temporaryKeyId *C.char, err_ **C.SealdError) C.int {
	err := sdkToGo(sealdSdk).DeleteGroupTMRTemporaryKey(C.GoString(groupId), C.GoString(temporaryKeyId))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	return C.int(0)
}

//export SealdSdk_SearchGroupTMRTemporaryKeys
func SealdSdk_SearchGroupTMRTemporaryKeys(sealdSdk *C.SealdSdk, tmrJWT *C.char, opts *C.SealdSearchGroupTMRTemporaryKeysOpts, nbPageFound *C.int, keysList **C.SealdGroupTMRTemporaryKeysArray, err_ **C.SealdError) C.int {
	nativeGTMRTK, err := sdkToGo(sealdSdk).SearchGroupTMRTemporaryKeys(C.GoString(tmrJWT), searchGroupTMRTemporaryKeysOptsToGo(opts))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*keysList = sliceToSealdGroupTMRTemporaryKeysArray(nativeGTMRTK.Keys)
	*nbPageFound = C.int(nativeGTMRTK.NbPage)
	return C.int(0)
}

//export SealdSdk_ConvertGroupTMRTemporaryKey
func SealdSdk_ConvertGroupTMRTemporaryKey(sealdSdk *C.SealdSdk, groupId *C.char, temporaryKeyId *C.char, tmrJWT *C.char, rawOverEncryptionKey *C.uchar, rawOverEncryptionKeyLen C.int, deleteOnConvert C.int, err_ **C.SealdError) C.int {
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(rawOverEncryptionKey), rawOverEncryptionKeyLen)
	err := sdkToGo(sealdSdk).ConvertGroupTMRTemporaryKey(C.GoString(groupId), C.GoString(temporaryKeyId), C.GoString(tmrJWT), overEncryptionKeyBytes, int(deleteOnConvert) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	return C.int(0)
}

// EncryptionSession

//export SealdSdk_CreateEncryptionSession
func SealdSdk_CreateEncryptionSession(sealdSdk *C.SealdSdk, recipients *C.SealdRecipientsWithRightsArray, metadata *C.char, useCache C.int, result **C.SealdEncryptionSession, err_ **C.SealdError) C.int {
	es, err := sdkToGo(sealdSdk).CreateEncryptionSession(
		recipientsWithRightsArrayToGo(recipients).getSlice(),
		sdk.CreateEncryptionSessionOptions{
			UseCache: int(useCache) != 0,
			Metadata: C.GoString(metadata),
		},
	)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goEncryptionSessionToC(es)
	return C.int(0)
}

//export SealdSdk_RetrieveEncryptionSession
func SealdSdk_RetrieveEncryptionSession(sealdSdk *C.SealdSdk, messageId *C.char, useCache C.int, lookupProxyKey C.int, lookupGroupKey C.int, result **C.SealdEncryptionSession, err_ **C.SealdError) C.int {
	es, err := sdkToGo(sealdSdk).RetrieveEncryptionSession(C.GoString(messageId), int(useCache) != 0, int(lookupProxyKey) != 0, int(lookupGroupKey) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goEncryptionSessionToC(es)
	return C.int(0)
}

//export SealdSdk_RetrieveEncryptionSessionFromMessage
func SealdSdk_RetrieveEncryptionSessionFromMessage(sealdSdk *C.SealdSdk, message *C.char, useCache C.int, lookupProxyKey C.int, lookupGroupKey C.int, result **C.SealdEncryptionSession, err_ **C.SealdError) C.int {
	es, err := sdkToGo(sealdSdk).RetrieveEncryptionSessionFromMessage(C.GoString(message), int(useCache) != 0, int(lookupProxyKey) != 0, int(lookupGroupKey) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goEncryptionSessionToC(es)
	return C.int(0)
}

//export SealdSdk_RetrieveEncryptionSessionFromFile
func SealdSdk_RetrieveEncryptionSessionFromFile(sealdSdk *C.SealdSdk, filePath *C.char, useCache C.int, lookupProxyKey C.int, lookupGroupKey C.int, result **C.SealdEncryptionSession, err_ **C.SealdError) C.int {
	es, err := sdkToGo(sealdSdk).RetrieveEncryptionSessionFromFile(C.GoString(filePath), int(useCache) != 0, int(lookupProxyKey) != 0, int(lookupGroupKey) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goEncryptionSessionToC(es)
	return C.int(0)
}

//export SealdSdk_RetrieveEncryptionSessionFromBytes
func SealdSdk_RetrieveEncryptionSessionFromBytes(sealdSdk *C.SealdSdk, fileBytes *C.uchar, fileBytesLen C.int, useCache C.int, lookupProxyKey C.int, lookupGroupKey C.int, result **C.SealdEncryptionSession, err_ **C.SealdError) C.int {
	fileBytesSlice := C.GoBytes(unsafe.Pointer(fileBytes), fileBytesLen)
	es, err := sdkToGo(sealdSdk).RetrieveEncryptionSessionFromBytes(fileBytesSlice, int(useCache) != 0, int(lookupProxyKey) != 0, int(lookupGroupKey) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goEncryptionSessionToC(es)
	return C.int(0)
}

//export SealdSdk_RetrieveEncryptionSessionByTmr
func SealdSdk_RetrieveEncryptionSessionByTmr(sealdSdk *C.SealdSdk, tmrJWT *C.char, sessionId *C.char, overEncryptionKey *C.uchar, overEncryptionKeyLen C.int, tmrAccessesRetrievalFilters *C.SealdTmrAccessesRetrievalFilters, tryIfMultiple C.int, useCache C.int, result **C.SealdEncryptionSession, err_ **C.SealdError) C.int {
	nativeJwtFilters := tmrAccessesRetrievalFiltersToGo(tmrAccessesRetrievalFilters)
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(overEncryptionKey), overEncryptionKeyLen)

	es, err := sdkToGo(sealdSdk).RetrieveEncryptionSessionByTmr(C.GoString(tmrJWT), C.GoString(sessionId), overEncryptionKeyBytes, nativeJwtFilters, int(tryIfMultiple) != 0, int(useCache) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = goEncryptionSessionToC(es)
	return C.int(0)
}

//export SealdSdk_RetrieveMultipleEncryptionSessions
func SealdSdk_RetrieveMultipleEncryptionSessions(sealdSdk *C.SealdSdk, sessionIds *C.SealdStringArray, useCache C.int, lookupProxyKey C.int, lookupGroupKey C.int, result **C.SealdEncryptionSessionArray, err_ **C.SealdError) C.int {
	encryptionSessions, err := sdkToGo(sealdSdk).RetrieveMultipleEncryptionSessions(stringArrayToGo(sessionIds).getSlice(), int(useCache) != 0, int(lookupProxyKey) != 0, int(lookupGroupKey) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = sliceToSealdEncryptionSessionArray(encryptionSessions)
	return C.int(0)
}

// Connectors

//export SealdSdk_GetSealdIdsFromConnectors
func SealdSdk_GetSealdIdsFromConnectors(sealdSdk *C.SealdSdk, connectorTypeValues *C.SealdConnectorTypeValueArray, result **C.SealdStringArray, err_ **C.SealdError) C.int {
	sealdIds, err := sdkToGo(sealdSdk).GetSealdIdsFromConnectors(connectorTypeValueArrayToGo(connectorTypeValues).getSlice())
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = sliceToStringArray(sealdIds)
	return C.int(0)
}

//export SealdSdk_GetConnectorsFromSealdId
func SealdSdk_GetConnectorsFromSealdId(sealdSdk *C.SealdSdk, sealdId *C.char, result **C.SealdConnectorsArray, err_ **C.SealdError) C.int {
	connectorsArray, err := sdkToGo(sealdSdk).GetConnectorsFromSealdId(C.GoString(sealdId))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = sliceToConnectorsArray(connectorsArray)
	return C.int(0)
}

//export SealdSdk_AddConnector
func SealdSdk_AddConnector(sealdSdk *C.SealdSdk, value *C.char, connectorType *C.char, preValidationToken *C.SealdPreValidationToken, result **C.SealdConnector, err_ **C.SealdError) C.int {
	res, err := sdkToGo(sealdSdk).AddConnector(
		C.GoString(value),
		common_models.ConnectorType(C.GoString(connectorType)),
		preValidationTokenToGo(preValidationToken),
	)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = connectorFromCommon(res)
	return C.int(0)
}

//export SealdSdk_ValidateConnector
func SealdSdk_ValidateConnector(sealdSdk *C.SealdSdk, connectorId *C.char, challenge *C.char, result **C.SealdConnector, err_ **C.SealdError) C.int {
	res, err := sdkToGo(sealdSdk).ValidateConnector(C.GoString(connectorId), C.GoString(challenge))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = connectorFromCommon(res)
	return C.int(0)
}

//export SealdSdk_RemoveConnector
func SealdSdk_RemoveConnector(sealdSdk *C.SealdSdk, connectorId *C.char, result **C.SealdConnector, err_ **C.SealdError) C.int {
	res, err := sdkToGo(sealdSdk).RemoveConnector(C.GoString(connectorId))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = connectorFromCommon(res)
	return C.int(0)
}

//export SealdSdk_ListConnectors
func SealdSdk_ListConnectors(sealdSdk *C.SealdSdk, result **C.SealdConnectorsArray, err_ **C.SealdError) C.int {
	connectorsArray, err := sdkToGo(sealdSdk).ListConnectors()
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = sliceToConnectorsArray(connectorsArray)
	return C.int(0)
}

//export SealdSdk_RetrieveConnector
func SealdSdk_RetrieveConnector(sealdSdk *C.SealdSdk, connectorId *C.char, result **C.SealdConnector, err_ **C.SealdError) C.int {
	res, err := sdkToGo(sealdSdk).RetrieveConnector(C.GoString(connectorId))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = connectorFromCommon(res)
	return C.int(0)
}

// Reencrypt

//export SealdSdk_MassReencrypt
func SealdSdk_MassReencrypt(sealdSdk *C.SealdSdk, deviceId *C.char, options C.SealdMassReencryptOptions, result *C.SealdMassReencryptResponse, err_ **C.SealdError) C.int {
	reencrypted, failed, err := sdkToGo(sealdSdk).MassReencrypt(C.GoString(deviceId), massReencryptOptionsToGo(options))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	result.Reencrypted = C.int(reencrypted)
	result.Failed = C.int(failed)
	return C.int(0)
}

//export SealdSdk_DevicesMissingKeys
func SealdSdk_DevicesMissingKeys(sealdSdk *C.SealdSdk, forceLocalAccountUpdate C.int, result **C.SealdDeviceMissingKeysArray, err_ **C.SealdError) C.int {
	response, err := sdkToGo(sealdSdk).DevicesMissingKeys(int(forceLocalAccountUpdate) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = sliceToDeviceMissingKeysArray(response)
	return C.int(0)
}

// Contact

//export SealdSdk_GetSigchainHash
func SealdSdk_GetSigchainHash(sealdSdk *C.SealdSdk, userId *C.char, position C.int, result **C.SealdGetSigchainResponse, err_ **C.SealdError) C.int {
	response, err := sdkToGo(sealdSdk).GetSigchainHash(C.GoString(userId), int(position))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}
	*result = getSigchainResponseFromGo(response)
	return C.int(0)
}

//export SealdSdk_CheckSigchainHash
func SealdSdk_CheckSigchainHash(sealdSdk *C.SealdSdk, userId *C.char, expectedHash *C.char, position C.int, result **C.SealdCheckSigchainResponse, err_ **C.SealdError) C.int {
	response, err := sdkToGo(sealdSdk).CheckSigchainHash(C.GoString(userId), C.GoString(expectedHash), int(position))
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = checkSigchainResponseFromGo(response)
	return C.int(0)
}

//export SealdSdk_ConvertTmrAccesses
func SealdSdk_ConvertTmrAccesses(sealdSdk *C.SealdSdk, tmrJWT *C.char, overEncryptionKey *C.uchar, overEncryptionKeyLen C.int, tmrAccessesConvertFilters *C.SealdTmrAccessesConvertFilters, deleteOnConvert C.int, result **C.SealdConvertTmrAccessesResult, err_ **C.SealdError) C.int {
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(overEncryptionKey), overEncryptionKeyLen)

	nativeJwtFilters := tmrAccessesConvertFiltersToGo(tmrAccessesConvertFilters)
	resp, err := sdkToGo(sealdSdk).ConvertTmrAccesses(C.GoString(tmrJWT), overEncryptionKeyBytes, nativeJwtFilters, int(deleteOnConvert) != 0)
	if err != nil {
		*err_ = sealdErrorFromGo(tracerr.Wrap(err))
		return C.int(-1)
	}

	*result = convertTmrAccessesResultFromGo(resp)
	return C.int(0)
}

func main() {}
