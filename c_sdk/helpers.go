package main

/*
#include <stdlib.h>
#include "./seald_sdk.h"
*/
import "C"
import (
	"fmt"
	"github.com/rs/zerolog"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/common_models"
	"go-seald-sdk/sdk"
	"go-seald-sdk/symmetric_key"
	"go-seald-sdk/utils"
	"sync"
	"time"
	"unsafe"
)

var (
	ErrorFileDbRequiresEncKeyC   = utils.NewSealdError("C_FILE_DB_REQUIRES_ENC_KEY", "Using a file database requires encryption key : if you pass DatabasePath you must also pass DatabaseEncryptionKey and DatabaseEncryptionKeyLen - C")
	ErrorFileDbInvalidKeyLengthC = utils.NewSealdError("C_FILE_DB_INVALID_KEY_LENGTH", "DatabaseEncryptionKey must be a 64-byte buffer - C")
)

func boolToCInt(b bool) C.int {
	if b {
		return C.int(1)
	} else {
		return C.int(0)
	}
}

// Helper SealdError

func sealdErrorFromGo(err error) *C.SealdError {
	serializedError := utils.ToSerializableError(err)
	res := (*C.SealdError)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdError{}))))
	res.Status = C.int(serializedError.Status)
	res.Code = C.CString(serializedError.Code)
	res.Id = C.CString(serializedError.Id)
	res.Description = C.CString(serializedError.Description)
	res.Details = C.CString(serializedError.Details)
	res.Raw = C.CString(serializedError.Raw)
	res.NativeStack = C.CString(serializedError.Stack)
	return res
}

//export SealdError_Free
func SealdError_Free(err *C.SealdError) {
	if err == nil {
		return
	}
	C.free(unsafe.Pointer(err.Code))
	C.free(unsafe.Pointer(err.Id))
	C.free(unsafe.Pointer(err.Description))
	C.free(unsafe.Pointer(err.Details))
	C.free(unsafe.Pointer(err.Raw))
	C.free(unsafe.Pointer(err.NativeStack))
	C.free(unsafe.Pointer(err))
}

// Helper SealdStringArray

type SealdStringArray struct {
	items []string
}

func stringArrayToGo(array *C.SealdStringArray) *SealdStringArray {
	if array == nil {
		return nil
	}
	return (*SealdStringArray)(unsafe.Pointer(array))
}

var sealdStringArrayRefMap = sync.Map{}

//export SealdStringArray_New
func SealdStringArray_New() *C.SealdStringArray {
	array := &SealdStringArray{}
	sealdStringArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdStringArray)(unsafe.Pointer(array))
}

//export SealdStringArray_Free
func SealdStringArray_Free(array *C.SealdStringArray) {
	sealdStringArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdStringArray_Add
func SealdStringArray_Add(array *C.SealdStringArray, s *C.char) {
	goArray := stringArrayToGo(array)
	goArray.items = append(goArray.items, C.GoString(s))
}

//export SealdStringArray_Get
func SealdStringArray_Get(array *C.SealdStringArray, i C.int) *C.char {
	goArray := stringArrayToGo(array)
	return C.CString(goArray.items[int(i)])
}

//export SealdStringArray_Size
func SealdStringArray_Size(array *C.SealdStringArray) C.int {
	goArray := stringArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdStringArray) getSlice() []string {
	if array == nil {
		return nil
	}
	return array.items
}

func sliceToStringArray(slice []string) *C.SealdStringArray {
	array := SealdStringArray_New()
	goArray := stringArrayToGo(array)
	goArray.items = append([]string{}, slice...)
	return array
}

// Helper SealdClearFile

//export SealdClearFile_Free
func SealdClearFile_Free(cf *C.SealdClearFile) {
	if cf == nil {
		return
	}
	C.free(unsafe.Pointer(cf.Filename))
	C.free(unsafe.Pointer(cf.SessionId))
	C.free(unsafe.Pointer(cf.FileContent))
	C.free(unsafe.Pointer(cf))
}

func clearFileFromCommon(cf *common_models.ClearFile) *C.SealdClearFile {
	res := (*C.SealdClearFile)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdClearFile{}))))
	res.Filename = C.CString(cf.Filename)
	res.SessionId = C.CString(cf.SessionId)
	res.FileContent = (*C.uchar)(C.CBytes(cf.FileContent))
	res.FileContentLen = C.int(len(cf.FileContent))
	return res
}

// Helper SealdAccountInfo

//export SealdAccountInfo_Free
func SealdAccountInfo_Free(info *C.SealdAccountInfo) {
	if info == nil {
		return
	}
	C.free(unsafe.Pointer(info.UserId))
	C.free(unsafe.Pointer(info.DeviceId))
	C.free(unsafe.Pointer(info))
}

func accountInfoFromCommon(accountInfo *sdk.AccountInfo) *C.SealdAccountInfo {
	res := (*C.SealdAccountInfo)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdAccountInfo{}))))
	res.UserId = C.CString(accountInfo.UserId)
	res.DeviceId = C.CString(accountInfo.DeviceId)
	if accountInfo.DeviceExpires != nil {
		res.DeviceExpires = C.longlong(accountInfo.DeviceExpires.Unix())
	} else {
		res.DeviceExpires = 0
	}
	return res
}

// Helper SealdInitializeOptions

func initializeOptionsToGo(cOpts *C.SealdInitializeOptions) (*sdk.InitializeOptions, error) {
	var storage sdk.Database
	if cOpts.DatabasePath == nil || *cOpts.DatabasePath == 0 { // NULL or empty string (first char is '\0')
		storage = &sdk.MemoryStorage{}
	} else {
		if cOpts.DatabaseEncryptionKeyLen != 64 {
			return nil, tracerr.Wrap(ErrorFileDbInvalidKeyLengthC)
		}
		if cOpts.DatabaseEncryptionKey == nil {
			return nil, tracerr.Wrap(ErrorFileDbRequiresEncKeyC)
		}
		encryptionKeyBytes := C.GoBytes(unsafe.Pointer(cOpts.DatabaseEncryptionKey), cOpts.DatabaseEncryptionKeyLen)
		key, err := symmetric_key.Decode(encryptionKeyBytes)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}
		storage = &sdk.FileStorage{
			EncryptionKey: key,
			DatabaseDir:   C.GoString(cOpts.DatabasePath),
		}
	}
	return &sdk.InitializeOptions{
		ApiURL:                    C.GoString(cOpts.ApiURL),
		AppId:                     C.GoString(cOpts.AppId),
		KeySize:                   int(cOpts.KeySize),
		EncryptionSessionCacheTTL: time.Duration(int64(cOpts.EncryptionSessionCacheTTL)) * time.Millisecond,
		LogLevel:                  zerolog.Level(int8(cOpts.LogLevel)),
		LogNoColor:                int(cOpts.LogNoColor) != 0,
		InstanceName:              C.GoString(cOpts.InstanceName),
		Platform:                  C.GoString(cOpts.Platform),
		Database:                  storage,
		LogWriter:                 logWriter,
	}, nil
}

//TODO: SealdInitializeOptions_Defaults

// Helper SealdCreateSubIdentityResponse

//export SealdCreateSubIdentityResponse_Free
func SealdCreateSubIdentityResponse_Free(resp *C.SealdCreateSubIdentityResponse) {
	if resp == nil {
		return
	}
	C.free(unsafe.Pointer(resp.DeviceId))
	C.free(unsafe.Pointer(resp.BackupKey))
	C.free(unsafe.Pointer(resp))
}

func createSubIdentityResponseFromCommon(createSubIdentityResponse *sdk.CreateSubIdentityResponse) *C.SealdCreateSubIdentityResponse {
	res := (*C.SealdCreateSubIdentityResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdCreateSubIdentityResponse{}))))
	res.DeviceId = C.CString(createSubIdentityResponse.DeviceId)
	res.BackupKey = (*C.uchar)(C.CBytes(createSubIdentityResponse.BackupKey))
	res.BackupKeyLen = C.int(len(createSubIdentityResponse.BackupKey))
	return res
}

// Helper SealdConnector

//export SealdConnector_Free
func SealdConnector_Free(c *C.SealdConnector) {
	if c == nil {
		return
	}
	C.free(unsafe.Pointer(c.SealdId))
	C.free(unsafe.Pointer(c.Type))
	C.free(unsafe.Pointer(c.Value))
	C.free(unsafe.Pointer(c.Id))
	C.free(unsafe.Pointer(c.State))
	C.free(unsafe.Pointer(c))
}

func connectorFromCommon(c *common_models.Connector) *C.SealdConnector {
	if c == nil {
		return nil
	}
	res := (*C.SealdConnector)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdConnector{}))))
	res.SealdId = C.CString(c.SealdId)
	res.Type = C.CString(string(c.Type))
	res.Value = C.CString(c.Value)
	res.Id = C.CString(c.Id)
	res.State = C.CString(string(c.State))
	return res
}

// Helper SealdPreValidationToken

func preValidationTokenToGo(t *C.SealdPreValidationToken) *utils.PreValidationToken {
	if t == nil {
		return nil
	}
	return &utils.PreValidationToken{
		DomainValidationKeyId: C.GoString(t.DomainValidationKeyId),
		Nonce:                 C.GoString(t.Nonce),
		Token:                 C.GoString(t.Token),
	}
}

//export SealdPreValidationToken_Free
func SealdPreValidationToken_Free(t *C.SealdPreValidationToken) {
	if t == nil {
		return
	}
	C.free(unsafe.Pointer(t.DomainValidationKeyId))
	C.free(unsafe.Pointer(t.Nonce))
	C.free(unsafe.Pointer(t.Token))
	C.free(unsafe.Pointer(t))
}

// Helper SealdConnectorsArray

type SealdConnectorsArray struct {
	items []*C.SealdConnector
}

func connectorsArrayToGo(array *C.SealdConnectorsArray) *SealdConnectorsArray {
	return (*SealdConnectorsArray)(unsafe.Pointer(array))
}

var sealdConnectorsArrayRefMap = sync.Map{}

//export SealdConnectorsArray_New
func SealdConnectorsArray_New() *C.SealdConnectorsArray {
	array := &SealdConnectorsArray{}
	sealdConnectorsArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdConnectorsArray)(unsafe.Pointer(array))
}

//export SealdConnectorsArray_Free
func SealdConnectorsArray_Free(array *C.SealdConnectorsArray) {
	goArray := connectorsArrayToGo(array)
	items := goArray.items
	goArray.items = nil
	for _, c := range items {
		SealdConnector_Free(c)
	}
	sealdConnectorsArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdConnectorsArray_Add
func SealdConnectorsArray_Add(array *C.SealdConnectorsArray, c *C.SealdConnector) {
	goArray := connectorsArrayToGo(array)
	goArray.items = append(goArray.items, c)
}

//export SealdConnectorsArray_Get
func SealdConnectorsArray_Get(array *C.SealdConnectorsArray, i C.int) *C.SealdConnector {
	goArray := connectorsArrayToGo(array)
	return goArray.items[int(i)]
}

//export SealdConnectorsArray_Size
func SealdConnectorsArray_Size(array *C.SealdConnectorsArray) C.int {
	goArray := connectorsArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdConnectorsArray) getSlice() []*C.SealdConnector {
	return array.items
}

func sliceToConnectorsArray(slice []common_models.Connector) *C.SealdConnectorsArray {
	ca := SealdConnectorsArray_New()
	for _, el := range slice {
		SealdConnectorsArray_Add(ca, connectorFromCommon(&el))
	}
	return ca
}

// Helper SealdConnectorTypeValueArray

type SealdConnectorTypeValueArray struct {
	items []*sdk.ConnectorTypeValue
}

func connectorTypeValueArrayToGo(array *C.SealdConnectorTypeValueArray) *SealdConnectorTypeValueArray {
	return (*SealdConnectorTypeValueArray)(unsafe.Pointer(array))
}

var sealdConnectorTypeValueArrayRefMap = sync.Map{}

//export SealdConnectorTypeValueArray_New
func SealdConnectorTypeValueArray_New() *C.SealdConnectorTypeValueArray {
	array := &SealdConnectorTypeValueArray{}
	sealdConnectorTypeValueArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdConnectorTypeValueArray)(unsafe.Pointer(array))
}

//export SealdConnectorTypeValueArray_Free
func SealdConnectorTypeValueArray_Free(array *C.SealdConnectorTypeValueArray) {
	sealdConnectorTypeValueArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdConnectorTypeValueArray_Add
func SealdConnectorTypeValueArray_Add(array *C.SealdConnectorTypeValueArray, connectorType *C.char, connectorValue *C.char) {
	goArray := connectorTypeValueArrayToGo(array)
	goArray.items = append(goArray.items, &sdk.ConnectorTypeValue{
		Type:  common_models.ConnectorType(C.GoString(connectorType)),
		Value: C.GoString(connectorValue),
	})
}

//export SealdConnectorTypeValueArray_Get
func SealdConnectorTypeValueArray_Get(array *C.SealdConnectorTypeValueArray, i C.int, connectorType **C.char, connectorValue **C.char) {
	goArray := connectorTypeValueArrayToGo(array)
	ctv := goArray.items[int(i)]
	*connectorType = C.CString(string(ctv.Type))
	*connectorValue = C.CString(ctv.Value)
}

//export SealdConnectorTypeValueArray_Size
func SealdConnectorTypeValueArray_Size(array *C.SealdConnectorTypeValueArray) C.int {
	goArray := connectorTypeValueArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdConnectorTypeValueArray) getSlice() []*sdk.ConnectorTypeValue {
	return array.items
}

// Helper SealdRecipientsWithRightsArray

type SealdRecipientsWithRightsArray struct {
	items []*sdk.RecipientWithRights
}

func recipientsWithRightsArrayToGo(array *C.SealdRecipientsWithRightsArray) *SealdRecipientsWithRightsArray {
	return (*SealdRecipientsWithRightsArray)(unsafe.Pointer(array))
}

var sealdRecipientsWithRightsArrayRefMap = sync.Map{}

//export SealdRecipientsWithRightsArray_New
func SealdRecipientsWithRightsArray_New() *C.SealdRecipientsWithRightsArray {
	array := &SealdRecipientsWithRightsArray{}
	sealdRecipientsWithRightsArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdRecipientsWithRightsArray)(unsafe.Pointer(array))
}

//export SealdRecipientsWithRightsArray_Free
func SealdRecipientsWithRightsArray_Free(array *C.SealdRecipientsWithRightsArray) {
	sealdRecipientsWithRightsArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdRecipientsWithRightsArray_Add
func SealdRecipientsWithRightsArray_Add(array *C.SealdRecipientsWithRightsArray, sealdId *C.char, readRight C.int, forwardRight C.int, revokeRight C.int) {
	goArray := recipientsWithRightsArrayToGo(array)
	goArray.items = append(goArray.items, &sdk.RecipientWithRights{
		Id: C.GoString(sealdId),
		Rights: &sdk.RecipientRights{
			Read:    readRight == 1,
			Forward: forwardRight == 1,
			Revoke:  revokeRight == 1,
		},
	})
}

//export SealdRecipientsWithRightsArray_AddWithDefaultRights
func SealdRecipientsWithRightsArray_AddWithDefaultRights(array *C.SealdRecipientsWithRightsArray, sealdId *C.char) {
	goArray := recipientsWithRightsArrayToGo(array)
	goArray.items = append(goArray.items, &sdk.RecipientWithRights{
		Id:     C.GoString(sealdId),
		Rights: nil,
	})
}

//export SealdRecipientsWithRightsArray_Get
func SealdRecipientsWithRightsArray_Get(array *C.SealdRecipientsWithRightsArray, i C.int, recipientId **C.char, recipientRightRead *C.int, recipientRightForward *C.int, recipientRightRevoke *C.int) {
	goArray := recipientsWithRightsArrayToGo(array)
	rwr := goArray.items[int(i)]
	*recipientId = C.CString(string(rwr.Id))

	if rwr.Rights != nil {
		*recipientRightRead = boolToCInt(rwr.Rights.Read)
		*recipientRightForward = boolToCInt(rwr.Rights.Forward)
		*recipientRightRevoke = boolToCInt(rwr.Rights.Revoke)
	} else {
		*recipientRightRead = C.int(-1)
		*recipientRightForward = C.int(-1)
		*recipientRightRevoke = C.int(-1)
	}
}

//export SealdRecipientsWithRightsArray_Size
func SealdRecipientsWithRightsArray_Size(array *C.SealdRecipientsWithRightsArray) C.int {
	goArray := recipientsWithRightsArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdRecipientsWithRightsArray) getSlice() []*sdk.RecipientWithRights {
	return array.items
}

// Helper SealdMassReencryptOptions

//export SealdMassReencryptOptions_Defaults
func SealdMassReencryptOptions_Defaults() C.SealdMassReencryptOptions {
	return C.SealdMassReencryptOptions{ // no need to do C.malloc and everything, as we are returning the struct itself on the stack
		Retries:                  3,
		RetrieveBatchSize:        1000,
		WaitBetweenRetries:       3.0,
		WaitProvisioning:         1,
		WaitProvisioningTime:     5.0,
		WaitProvisioningTimeMax:  10.0,
		WaitProvisioningTimeStep: 1.0,
		WaitProvisioningRetries:  100,
		ForceLocalAccountUpdate:  0,
	}
}

func massReencryptOptionsToGo(o C.SealdMassReencryptOptions) sdk.MassReencryptOptions {
	return sdk.MassReencryptOptions{
		Retries:                  int(o.Retries),
		RetrieveBatchSize:        int(o.RetrieveBatchSize),
		WaitBetweenRetries:       time.Duration(int64(o.WaitBetweenRetries)) * time.Millisecond,
		WaitProvisioning:         int(o.WaitProvisioning) != 0,
		WaitProvisioningTime:     time.Duration(int64(o.WaitProvisioningTime)) * time.Millisecond,
		WaitProvisioningTimeMax:  time.Duration(int64(o.WaitProvisioningTimeMax)) * time.Millisecond,
		WaitProvisioningTimeStep: time.Duration(int64(o.WaitProvisioningTimeStep)) * time.Millisecond,
		WaitProvisioningRetries:  int(o.WaitProvisioningRetries),
		ForceLocalAccountUpdate:  int(o.ForceLocalAccountUpdate) != 0,
	}
}

// Helper SealdDeviceMissingKeys

func deviceMissingKeysFromGo(d *sdk.DeviceMissingKeys) *C.SealdDeviceMissingKeys {
	res := (*C.SealdDeviceMissingKeys)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdDeviceMissingKeys{}))))
	res.DeviceId = C.CString(d.DeviceId)
	return res
}

//export SealdDeviceMissingKeys_Free
func SealdDeviceMissingKeys_Free(d *C.SealdDeviceMissingKeys) {
	if d == nil {
		return
	}
	C.free(unsafe.Pointer(d.DeviceId))
	C.free(unsafe.Pointer(d))
}

// Helper SealdDeviceMissingKeysArray

type SealdDeviceMissingKeysArray struct {
	items []*C.SealdDeviceMissingKeys
}

func deviceMissingKeysArrayToGo(array *C.SealdDeviceMissingKeysArray) *SealdDeviceMissingKeysArray {
	return (*SealdDeviceMissingKeysArray)(unsafe.Pointer(array))
}

var sealdDeviceMissingKeysArrayRefMap = sync.Map{}

//export SealdDeviceMissingKeysArray_New
func SealdDeviceMissingKeysArray_New() *C.SealdDeviceMissingKeysArray {
	array := &SealdDeviceMissingKeysArray{}
	sealdDeviceMissingKeysArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdDeviceMissingKeysArray)(unsafe.Pointer(array))
}

//export SealdDeviceMissingKeysArray_Free
func SealdDeviceMissingKeysArray_Free(array *C.SealdDeviceMissingKeysArray) {
	goArray := deviceMissingKeysArrayToGo(array)
	items := goArray.items
	goArray.items = nil
	for _, c := range items {
		SealdDeviceMissingKeys_Free(c)
	}
	sealdDeviceMissingKeysArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdDeviceMissingKeysArray_Add
func SealdDeviceMissingKeysArray_Add(array *C.SealdDeviceMissingKeysArray, d *C.SealdDeviceMissingKeys) {
	goArray := deviceMissingKeysArrayToGo(array)
	goArray.items = append(goArray.items, d)
}

//export SealdDeviceMissingKeysArray_Get
func SealdDeviceMissingKeysArray_Get(array *C.SealdDeviceMissingKeysArray, i C.int) *C.SealdDeviceMissingKeys {
	goArray := deviceMissingKeysArrayToGo(array)
	return goArray.items[int(i)]
}

//export SealdDeviceMissingKeysArray_Size
func SealdDeviceMissingKeysArray_Size(array *C.SealdDeviceMissingKeysArray) C.int {
	goArray := deviceMissingKeysArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdDeviceMissingKeysArray) getSlice() []*C.SealdDeviceMissingKeys {
	return array.items
}

func sliceToDeviceMissingKeysArray(slice []sdk.DeviceMissingKeys) *C.SealdDeviceMissingKeysArray {
	ca := SealdDeviceMissingKeysArray_New()
	for _, el := range slice {
		SealdDeviceMissingKeysArray_Add(ca, deviceMissingKeysFromGo(&el))
	}
	return ca
}

// Helper SealdActionStatus

//export SealdActionStatus_Free
func SealdActionStatus_Free(as *C.SealdActionStatus) {
	if as == nil {
		return
	}
	C.free(unsafe.Pointer(as.Id))
	C.free(unsafe.Pointer(as.ErrorCode))
	C.free(unsafe.Pointer(as.Result))
	C.free(unsafe.Pointer(as))
}

// Helper SealdActionStatusArray

type SealdActionStatusArray struct {
	items []*C.SealdActionStatus
}

var sealdActionStatusArrayRefMap = sync.Map{}

//export SealdActionStatusArray_New
func SealdActionStatusArray_New() *C.SealdActionStatusArray {
	array := &SealdActionStatusArray{}
	sealdActionStatusArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdActionStatusArray)(unsafe.Pointer(array))
}

func actionStatusArrayToGo(array *C.SealdActionStatusArray) *SealdActionStatusArray {
	return (*SealdActionStatusArray)(unsafe.Pointer(array))
}

//export SealdActionStatusArray_Add
func SealdActionStatusArray_Add(array *C.SealdActionStatusArray, as *C.SealdActionStatus) {
	goArray := actionStatusArrayToGo(array)
	goArray.items = append(goArray.items, as)
}

//export SealdActionStatusArray_Free
func SealdActionStatusArray_Free(array *C.SealdActionStatusArray) {
	goArray := actionStatusArrayToGo(array)
	items := goArray.items
	goArray.items = nil
	for _, as := range items {
		SealdActionStatus_Free(as)
	}
	sealdActionStatusArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdActionStatusArray_Size
func SealdActionStatusArray_Size(array *C.SealdActionStatusArray) C.int {
	goArray := actionStatusArrayToGo(array)
	return C.int(len(goArray.items))
}

//export SealdActionStatusArray_Get
func SealdActionStatusArray_Get(array *C.SealdActionStatusArray, i C.int) *C.SealdActionStatus {
	goArray := actionStatusArrayToGo(array)
	return goArray.items[int(i)]
}

func actionStatusArrayFromAddKey(addKeyResp *sdk.AddKeysMultiStatusResponse) *C.SealdActionStatusArray {
	asArray := SealdActionStatusArray_New()
	for key, addKeysResp := range addKeyResp.Status {
		as := (*C.SealdActionStatus)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdActionStatus{}))))
		as.Id = C.CString(key)
		as.Success = boolToCInt(addKeysResp.StatusCode == 200)
		as.Result = nil // So that it will be a null pointer for the Flutter bindings

		if addKeysResp.Error != nil {
			as.ErrorCode = C.CString(fmt.Sprintf("%s %s", addKeysResp.Error.Id, addKeysResp.Error.Code))
		} else {
			as.ErrorCode = nil
		}
		SealdActionStatusArray_Add(asArray, as)
	}

	return asArray
}

func actionStatusArrayFromRevoke(revokeMap map[string]string) *C.SealdActionStatusArray {
	asArray := SealdActionStatusArray_New()
	for uid, status := range revokeMap {
		as := (*C.SealdActionStatus)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdActionStatus{}))))
		as.Id = C.CString(uid)
		as.Result = nil // So that it will be a null pointer for the Flutter bindings
		as.Success = boolToCInt(status == "ok")
		as.ErrorCode = nil
		SealdActionStatusArray_Add(asArray, as)
	}

	return asArray
}

func actionStatusArrayFromAddTmrAccess(addTmrAccessResp *sdk.AddTmrAccessesMultiStatusResponse) *C.SealdActionStatusArray {
	asArray := SealdActionStatusArray_New()
	for key, added := range addTmrAccessResp.Status {
		as := (*C.SealdActionStatus)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdActionStatus{}))))
		as.Id = C.CString(key)
		as.Success = boolToCInt(added.Status == 200)
		as.Result = C.CString(added.TmrKey.Id)

		if added.Error != nil {
			as.ErrorCode = C.CString(fmt.Sprintf("%s %s", added.Error.Status, added.Error.Code))
		} else {
			as.ErrorCode = nil
		}
		SealdActionStatusArray_Add(asArray, as)
	}

	return asArray
}

// Helper SealdRevokeResult

//export SealdRevokeResult_Free
func SealdRevokeResult_Free(rr *C.SealdRevokeResult) {
	if rr == nil {
		return
	}
	SealdActionStatusArray_Free(rr.Recipients)
	SealdActionStatusArray_Free(rr.ProxySessions)
	C.free(unsafe.Pointer(rr))
}

func revokeResultFromGo(recipients map[string]string, proxySessions map[string]string) *C.SealdRevokeResult {
	res := (*C.SealdRevokeResult)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdRevokeResult{}))))
	res.Recipients = actionStatusArrayFromRevoke(recipients)
	res.ProxySessions = actionStatusArrayFromRevoke(proxySessions)
	return res
}

// Helper SealdEncryptionSessionRetrievalDetails

//export SealdEncryptionSessionRetrievalDetails_Free
func SealdEncryptionSessionRetrievalDetails_Free(details *C.SealdEncryptionSessionRetrievalDetails) {
	if details == nil {
		return
	}
	C.free(unsafe.Pointer(details.GroupId))
	C.free(unsafe.Pointer(details.ProxySessionId))
	C.free(unsafe.Pointer(details))
}

func retrievalDetailsFromGo(d sdk.EncryptionSessionRetrievalDetails) *C.SealdEncryptionSessionRetrievalDetails {
	res := (*C.SealdEncryptionSessionRetrievalDetails)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdEncryptionSessionRetrievalDetails{}))))
	res.Flow = C.SealdEncryptionSessionRetrievalFlow(d.Flow)
	res.GroupId = utils.Ternary(d.GroupId != "", C.CString(d.GroupId), nil)
	res.ProxySessionId = utils.Ternary(d.ProxySessionId != "", C.CString(d.ProxySessionId), nil)
	res.FromCache = boolToCInt(d.FromCache)
	return res
}

// Helper SealdGetSigchainResponse

//export SealdGetSigchainResponse_Free
func SealdGetSigchainResponse_Free(sigchainInfo *C.SealdGetSigchainResponse) {
	if sigchainInfo == nil {
		return
	}
	C.free(unsafe.Pointer(sigchainInfo.Hash))
	C.free(unsafe.Pointer(sigchainInfo))
}

func getSigchainResponseFromGo(sigchainInfo *sdk.GetSigchainResponse) *C.SealdGetSigchainResponse {
	res := (*C.SealdGetSigchainResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdGetSigchainResponse{}))))
	res.Hash = C.CString(sigchainInfo.Hash)
	res.Position = C.int(sigchainInfo.Position)
	return res
}

// Helper SealdCheckSigchainResponse

func checkSigchainResponseFromGo(sigchainInfo *sdk.CheckSigchainResponse) *C.SealdCheckSigchainResponse {
	res := (*C.SealdCheckSigchainResponse)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdCheckSigchainResponse{}))))
	res.Found = boolToCInt(sigchainInfo.Found)
	res.Position = C.int(sigchainInfo.Position)
	res.LastPosition = C.int(sigchainInfo.LastPosition)
	return res
}

func b64KeyToNative(b64Key *C.char) (*symmetric_key.SymKey, error) {
	decodedSymKey, err := utils.Base64DecodeString(C.GoString(b64Key))
	if err != nil {
		return nil, err
	}
	overEncryptionKey, err := symmetric_key.Decode(decodedSymKey)
	if err != nil {
		return nil, err
	}
	return &overEncryptionKey, nil
}

// Helper SealdTmrAccessesRetrievalFilters

func tmrAccessesRetrievalFiltersToGo(cFilters *C.SealdTmrAccessesRetrievalFilters) *sdk.TmrAccessesRetrievalFilters {
	if cFilters == nil {
		return nil
	}
	return &sdk.TmrAccessesRetrievalFilters{
		CreatedById: C.GoString(cFilters.CreatedById),
		TmrAccessId: C.GoString(cFilters.TmrAccessId),
	}
}

//export SealdTmrAccessesRetrievalFilters_Free
func SealdTmrAccessesRetrievalFilters_Free(filters *C.SealdTmrAccessesRetrievalFilters) {
	if filters == nil {
		return
	}
	C.free(unsafe.Pointer(filters.CreatedById))
	C.free(unsafe.Pointer(filters.TmrAccessId))
}

// Helper SealdTmrAccessesConvertFilters

func tmrAccessesConvertFiltersToGo(cFilters *C.SealdTmrAccessesConvertFilters) *sdk.TmrAccessesConvertFilters {
	if cFilters == nil {
		return nil
	}
	return &sdk.TmrAccessesConvertFilters{
		SessionId:   C.GoString(cFilters.SessionId),
		CreatedById: C.GoString(cFilters.CreatedById),
		TmrAccessId: C.GoString(cFilters.TmrAccessId),
	}
}

//export SealdTmrAccessesConvertFilters_Free
func SealdTmrAccessesConvertFilters_Free(filters *C.SealdTmrAccessesConvertFilters) {
	if filters == nil {
		return
	}
	C.free(unsafe.Pointer(filters.SessionId))
	C.free(unsafe.Pointer(filters.CreatedById))
	C.free(unsafe.Pointer(filters.TmrAccessId))
}

// Helper SealdConvertTmrAccessesResult

//export SealdConvertTmrAccessesResult_Free
func SealdConvertTmrAccessesResult_Free(convAccess *C.SealdConvertTmrAccessesResult) {
	if convAccess == nil {
		return
	}
	SealdStringArray_Free(convAccess.Converted)
	C.free(unsafe.Pointer(convAccess))
}

func convertTmrAccessesResultFromGo(resp *sdk.ConvertTmrAccessesResponse) *C.SealdConvertTmrAccessesResult {
	res := (*C.SealdConvertTmrAccessesResult)(C.malloc(C.size_t(unsafe.Sizeof(C.SealdConvertTmrAccessesResult{}))))
	res.Status = C.CString(resp.Status)
	res.Converted = sliceToStringArray(resp.Converted)
	res.Succeeded = C.int(len(resp.Succeeded))
	res.Errored = C.int(len(resp.Errored))
	return res
}

// Helper SealdTmrRecipientsWithRightsArray

type SealdTmrRecipientsWithRightsArray struct {
	items []*sdk.TmrRecipientWithRights
}

func tmrRecipientsWithRightsArrayToGo(array *C.SealdTmrRecipientsWithRightsArray) *SealdTmrRecipientsWithRightsArray {
	return (*SealdTmrRecipientsWithRightsArray)(unsafe.Pointer(array))
}

var SealdTmrRecipientsWithRightsArrayRefMap = sync.Map{}

//export SealdTmrRecipientsWithRightsArray_New
func SealdTmrRecipientsWithRightsArray_New() *C.SealdTmrRecipientsWithRightsArray {
	array := &SealdTmrRecipientsWithRightsArray{}
	SealdTmrRecipientsWithRightsArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdTmrRecipientsWithRightsArray)(unsafe.Pointer(array))
}

//export SealdTmrRecipientsWithRightsArray_Free
func SealdTmrRecipientsWithRightsArray_Free(array *C.SealdTmrRecipientsWithRightsArray) {
	SealdTmrRecipientsWithRightsArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdTmrRecipientsWithRightsArray_Add
func SealdTmrRecipientsWithRightsArray_Add(array *C.SealdTmrRecipientsWithRightsArray, authFactorType *C.char, authFactorValue *C.char, overEncryptionKey *C.uchar, overEncryptionKeyLen C.int, readRight C.int, forwardRight C.int, revokeRight C.int) {
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(overEncryptionKey), overEncryptionKeyLen)

	goArray := tmrRecipientsWithRightsArrayToGo(array)
	goArray.items = append(goArray.items, &sdk.TmrRecipientWithRights{
		AuthFactor: &common_models.AuthFactor{
			Type:  C.GoString(authFactorType),
			Value: C.GoString(authFactorValue),
		},
		OverEncryptionKey: overEncryptionKeyBytes,
		Rights: &sdk.RecipientRights{
			Read:    readRight == 1,
			Forward: forwardRight == 1,
			Revoke:  revokeRight == 1,
		},
	})
}

//export SealdTmrRecipientsWithRightsArray_AddWithDefaultRights
func SealdTmrRecipientsWithRightsArray_AddWithDefaultRights(array *C.SealdTmrRecipientsWithRightsArray, authFactorType *C.char, authFactorValue *C.char, overEncryptionKey *C.uchar, overEncryptionKeyLen C.int) {
	overEncryptionKeyBytes := C.GoBytes(unsafe.Pointer(overEncryptionKey), overEncryptionKeyLen)

	goArray := tmrRecipientsWithRightsArrayToGo(array)
	goArray.items = append(goArray.items, &sdk.TmrRecipientWithRights{
		AuthFactor: &common_models.AuthFactor{
			Type:  C.GoString(authFactorType),
			Value: C.GoString(authFactorValue),
		},
		OverEncryptionKey: overEncryptionKeyBytes,
		Rights:            nil,
	})
}

//export SealdTmrRecipientsWithRightsArray_Get
func SealdTmrRecipientsWithRightsArray_Get(array *C.SealdTmrRecipientsWithRightsArray, i C.int, authFactorType **C.char, authFactorValue **C.char, overEncryptionKey **C.uchar, overEncryptionKeyLen *C.int, recipientRightRead *C.int, recipientRightForward *C.int, recipientRightRevoke *C.int) {
	goArray := tmrRecipientsWithRightsArrayToGo(array)
	tmrR := goArray.items[int(i)]

	*authFactorType = C.CString(tmrR.AuthFactor.Type)
	*authFactorValue = C.CString(tmrR.AuthFactor.Value)

	*overEncryptionKey = (*C.uchar)(C.CBytes(tmrR.OverEncryptionKey))
	*overEncryptionKeyLen = C.int(len(tmrR.OverEncryptionKey))

	*recipientRightRead = boolToCInt(tmrR.Rights.Read)
	*recipientRightForward = boolToCInt(tmrR.Rights.Forward)
	*recipientRightRevoke = boolToCInt(tmrR.Rights.Revoke)
}

//export SealdTmrRecipientsWithRightsArray_Size
func SealdTmrRecipientsWithRightsArray_Size(array *C.SealdTmrRecipientsWithRightsArray) C.int {
	goArray := tmrRecipientsWithRightsArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdTmrRecipientsWithRightsArray) getSlice() []*sdk.TmrRecipientWithRights {
	return array.items
}

// Helper SealdEncryptionSessionArray

type SealdEncryptionSessionArray struct {
	items []*sdk.EncryptionSession
}

func sealdEncryptionSessionArrayToGo(array *C.SealdEncryptionSessionArray) *SealdEncryptionSessionArray {
	return (*SealdEncryptionSessionArray)(unsafe.Pointer(array))
}

var sealdEncryptionSessionArrayRefMap = sync.Map{}

//export SealdEncryptionSessionArray_New
func SealdEncryptionSessionArray_New() *C.SealdEncryptionSessionArray {
	array := &SealdEncryptionSessionArray{}
	sealdEncryptionSessionArrayRefMap.Store(uintptr(unsafe.Pointer(array)), array)
	return (*C.SealdEncryptionSessionArray)(unsafe.Pointer(array))
}

//export SealdEncryptionSessionArray_Free
func SealdEncryptionSessionArray_Free(array *C.SealdEncryptionSessionArray) {
	sealdEncryptionSessionArrayRefMap.Delete(uintptr(unsafe.Pointer(array)))
}

//export SealdEncryptionSessionArray_Add
func SealdEncryptionSessionArray_Add(array *C.SealdEncryptionSessionArray, es *C.SealdEncryptionSession) {
	goArray := sealdEncryptionSessionArrayToGo(array)
	goArray.items = append(goArray.items, encryptionSessionToGo(es))
}

//export SealdEncryptionSessionArray_Get
func SealdEncryptionSessionArray_Get(array *C.SealdEncryptionSessionArray, i C.int) *C.SealdEncryptionSession {
	goArray := sealdEncryptionSessionArrayToGo(array)
	return goEncryptionSessionToC(goArray.items[int(i)])
}

//export SealdEncryptionSessionArray_Size
func SealdEncryptionSessionArray_Size(array *C.SealdEncryptionSessionArray) C.int {
	goArray := sealdEncryptionSessionArrayToGo(array)
	return C.int(len(goArray.items))
}

func (array *SealdEncryptionSessionArray) getSlice() []*sdk.EncryptionSession {
	return array.items
}

func sliceToSealdEncryptionSessionArray(slice []*sdk.EncryptionSession) *C.SealdEncryptionSessionArray {
	array := SealdEncryptionSessionArray_New()
	goArray := sealdEncryptionSessionArrayToGo(array)
	goArray.items = append([]*sdk.EncryptionSession{}, slice...)
	return array
}
