package mobile_sdk

import (
	"fmt"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/sdk"
	"go-seald-sdk/utils"
)

type MobileEncryptionSession struct {
	Id               string
	RetrievalDetails *EncryptionSessionRetrievalDetails
	es               *sdk.EncryptionSession
}

func mobileEncryptionSessionFromCommon(es *sdk.EncryptionSession) *MobileEncryptionSession {
	return &MobileEncryptionSession{
		es:               es,
		Id:               es.Id,
		RetrievalDetails: retrievalDetailsFromCommon(es.RetrievalDetails),
	}
}

type ClearFile struct {
	Filename    string
	SessionId   string
	FileContent []byte
}

type EncryptionSessionRetrievalDetails struct {
	Flow           int
	GroupId        string
	ProxySessionId string
	FromCache      bool
}

func retrievalDetailsFromCommon(details sdk.EncryptionSessionRetrievalDetails) *EncryptionSessionRetrievalDetails {
	return &EncryptionSessionRetrievalDetails{
		Flow:           int(details.Flow),
		GroupId:        details.GroupId,
		ProxySessionId: details.ProxySessionId,
		FromCache:      details.FromCache,
	}
}

func (encryptionSession *MobileEncryptionSession) AddRecipients(recipients *RecipientsWithRightsArray) (*ActionStatusArray, error) {
	resp, err := encryptionSession.es.AddRecipients(recipients.getSlice())
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}

	msArray := &ActionStatusArray{}
	for key, addKeysResp := range resp.Status {
		as := &ActionStatus{
			Id:      key,
			Success: addKeysResp.StatusCode == 200,
		}
		if addKeysResp.Error != nil {
			as.ErrorCode = fmt.Sprintf("%s %s", addKeysResp.Error.Id, addKeysResp.Error.Code)
		}
		msArray.Add(as)
	}
	return msArray, nil
}

func (encryptionSession *MobileEncryptionSession) AddProxySession(proxySessionId string, rights *RecipientRights) error {
	err := encryptionSession.es.AddProxySession(proxySessionId, rights.toCommon())
	if err != nil {
		return utils.ToSerializableError(tracerr.Wrap(err))
	}
	return nil
}

func (encryptionSession *MobileEncryptionSession) RevokeRecipients(recipientsIds *StringArray, proxySessionsIds *StringArray) (*RevokeResult, error) {
	resp, err := encryptionSession.es.RevokeRecipients(recipientsIds.getSlice(), proxySessionsIds.getSlice())
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return revokeResultFromCommon(resp.UserIds, resp.ProxyMkIds), nil
}

func (encryptionSession *MobileEncryptionSession) RevokeAll() (*RevokeResult, error) {
	resp, err := encryptionSession.es.RevokeAll()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return revokeResultFromCommon(resp.RevokeAll.UserIds, resp.RevokeAll.ProxyMkIds), nil
}

func (encryptionSession *MobileEncryptionSession) RevokeOthers() (*RevokeResult, error) {
	resp, err := encryptionSession.es.RevokeOthers()
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return revokeResultFromCommon(resp.RevokeAll.UserIds, resp.RevokeAll.ProxyMkIds), nil
}

func (encryptionSession *MobileEncryptionSession) EncryptMessage(clearMessage string) (string, error) {
	res, err := encryptionSession.es.EncryptMessage(clearMessage)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (encryptionSession *MobileEncryptionSession) DecryptMessage(clearMessage string) (string, error) {
	res, err := encryptionSession.es.DecryptMessage(clearMessage)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (encryptionSession *MobileEncryptionSession) EncryptFile(clearFile []byte, filename string) ([]byte, error) {
	res, err := encryptionSession.es.EncryptFile(clearFile, filename)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}
func (encryptionSession *MobileEncryptionSession) DecryptFile(encryptedFile []byte) (*ClearFile, error) {
	res, err := encryptionSession.es.DecryptFile(encryptedFile)
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}
	return &ClearFile{Filename: res.Filename, SessionId: res.SessionId, FileContent: res.FileContent}, nil
}

func (encryptionSession *MobileEncryptionSession) EncryptFileFromURI(clearFileURI string) (string, error) {
	res, err := encryptionSession.es.EncryptFileFromPath(clearFileURI)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (encryptionSession *MobileEncryptionSession) DecryptFileFromURI(encryptedFileURI string) (string, error) {
	res, err := encryptionSession.es.DecryptFileFromPath(encryptedFileURI)
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}
	return res, nil
}

func (encryptionSession *MobileEncryptionSession) AddTmrAccess(tmrRecipient *TmrRecipientWithRights) (string, error) {
	accessId, err := encryptionSession.es.AddTmrAccess(tmrRecipient.toCommon())
	if err != nil {
		return "", utils.ToSerializableError(tracerr.Wrap(err))
	}

	return accessId, nil
}

func (encryptionSession *MobileEncryptionSession) AddMultipleTmrAccesses(recipients *TmrRecipientWithRightsArray) (*ActionStatusArray, error) {
	resp, err := encryptionSession.es.AddMultipleTmrAccesses(recipients.getSlice())
	if err != nil {
		return nil, utils.ToSerializableError(tracerr.Wrap(err))
	}

	msArray := &ActionStatusArray{}
	for afValue, addTmrResp := range resp.Status {
		as := &ActionStatus{
			Id:      afValue,
			Success: addTmrResp.Status == 200,
		}
		if addTmrResp.Error != nil {
			as.ErrorCode = fmt.Sprintf("%s %s", addTmrResp.Error.Code, addTmrResp.Error.Status)
		}
		if as.Success {
			as.Result = addTmrResp.TmrKey.Id
		}
		msArray.Add(as)
	}
	return msArray, nil
}
