package mobile_sdk

import (
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk"
)

func sliceToStringArray(slice []string) *StringArray {
	array := &StringArray{}
	for _, el := range slice {
		array = array.Add(el)
	}
	return array

}

type StringArray struct {
	items []string
}

func (array *StringArray) Add(s string) *StringArray {
	array.items = append(array.items, s)
	return array
}
func (array *StringArray) Get(i int) string {
	return array.items[i]
}
func (array *StringArray) Size() int {
	return len(array.items)
}
func (array *StringArray) getSlice() []string {
	if array == nil {
		return nil
	}
	return array.items
}

type Connector struct { // Simplified model of connector
	SealdId string
	Type    string
	Value   string
	Id      string
	State   string
}

type ConnectorsArray struct {
	items []common_models.Connector
}

func (s *Connector) toCommon() *common_models.Connector {
	if s == nil {
		return nil
	}
	return &common_models.Connector{
		SealdId: s.SealdId,
		Type:    common_models.ConnectorType(s.Type),
		Value:   s.Value,
		Id:      s.Id,
		State:   common_models.ConnectorState(s.State),
	}
}

func connectorFromCommon(s *common_models.Connector) *Connector {
	if s == nil {
		return nil
	}
	return &Connector{
		SealdId: s.SealdId,
		Type:    string(s.Type),
		Value:   s.Value,
		Id:      s.Id,
		State:   string(s.State),
	}
}

func (array *ConnectorsArray) Add(s *Connector) *ConnectorsArray {
	array.items = append(array.items, *s.toCommon())
	return array
}
func (array *ConnectorsArray) Get(i int) *Connector {
	return connectorFromCommon(&array.items[i])
}
func (array *ConnectorsArray) Size() int {
	return len(array.items)
}
func (array *ConnectorsArray) getSlice() []common_models.Connector {
	if array == nil {
		return nil
	}
	return array.items
}

type ConnectorTypeValue struct {
	Type  string // I have to redefine the ConnectorTypeValue here, because gomobile does not like custom types like ConnectorType
	Value string
}

type ConnectorTypeValueArray struct {
	items []*sdk.ConnectorTypeValue
}

func (s *ConnectorTypeValue) toCommon() *sdk.ConnectorTypeValue {
	if s == nil {
		return nil
	}
	return &sdk.ConnectorTypeValue{
		Type:  common_models.ConnectorType(s.Type),
		Value: s.Value,
	}
}

func connectorTypeValueFromCommon(s *sdk.ConnectorTypeValue) *ConnectorTypeValue {
	if s == nil {
		return nil
	}
	return &ConnectorTypeValue{
		Type:  string(s.Type),
		Value: s.Value,
	}
}

func (array *ConnectorTypeValueArray) Add(s *ConnectorTypeValue) *ConnectorTypeValueArray {
	array.items = append(array.items, s.toCommon())
	return array
}
func (array *ConnectorTypeValueArray) Get(i int) *ConnectorTypeValue {
	return connectorTypeValueFromCommon(array.items[i])
}
func (array *ConnectorTypeValueArray) Size() int {
	return len(array.items)
}
func (array *ConnectorTypeValueArray) getSlice() []*sdk.ConnectorTypeValue {
	if array == nil {
		return nil
	}
	return array.items
}

type DeviceMissingKeys struct {
	DeviceId string
}

func deviceMissingKeysFromCommon(d *sdk.DeviceMissingKeys) *DeviceMissingKeys {
	return &DeviceMissingKeys{DeviceId: d.DeviceId}
}

type DevicesMissingKeysArray struct {
	items []sdk.DeviceMissingKeys
}

func devicesMissingKeysArrayFromCommon(array []sdk.DeviceMissingKeys) *DevicesMissingKeysArray {
	return &DevicesMissingKeysArray{items: array}
}
func (array *DevicesMissingKeysArray) Get(i int) *DeviceMissingKeys {
	return deviceMissingKeysFromCommon(&array.items[i])
}
func (array *DevicesMissingKeysArray) Size() int {
	return len(array.items)
}

type ActionStatus struct {
	Id        string
	Success   bool
	ErrorCode string
	Result    string
}
type ActionStatusArray struct {
	status []ActionStatus
}

func (asArray *ActionStatusArray) Add(s *ActionStatus) *ActionStatusArray {
	asArray.status = append(asArray.status, *s)
	return asArray
}
func (asArray *ActionStatusArray) Get(i int) *ActionStatus {
	return &asArray.status[i]
}
func (asArray *ActionStatusArray) Size() int {
	return len(asArray.status)
}
func (asArray *ActionStatusArray) getSlice() []ActionStatus {
	if asArray == nil {
		return nil
	}
	return asArray.status
}

type RevokeResult struct {
	Recipients    *ActionStatusArray
	ProxySessions *ActionStatusArray
}

func revokeResultFromCommon(recipientsResults map[string]string, proxySessionsResults map[string]string) *RevokeResult {
	recipientsArray := &ActionStatusArray{}
	for uid, status := range recipientsResults {
		recipientsArray.Add(&ActionStatus{
			Id:      uid,
			Success: status == "ok",
		})
	}
	proxySessionsArray := &ActionStatusArray{}
	for uid, status := range proxySessionsResults {
		proxySessionsArray.Add(&ActionStatus{
			Id:      uid,
			Success: status == "ok",
		})
	}

	return &RevokeResult{
		Recipients:    recipientsArray,
		ProxySessions: proxySessionsArray,
	}
}

type RecipientRights struct {
	Read    bool
	Revoke  bool
	Forward bool
}

func (s *RecipientRights) toCommon() *sdk.RecipientRights {
	if s == nil {
		return nil
	}
	return &sdk.RecipientRights{
		Read:    s.Read,
		Revoke:  s.Revoke,
		Forward: s.Forward,
	}
}
func recipientRightsFromCommon(s *sdk.RecipientRights) *RecipientRights {
	if s == nil {
		return nil
	}
	return &RecipientRights{
		Read:    s.Read,
		Revoke:  s.Revoke,
		Forward: s.Forward,
	}
}

type RecipientWithRights struct {
	RecipientId string // Never call a key `Id`. In obj-c, every instance has a key `id` used internally
	Rights      *RecipientRights
}

func (s *RecipientWithRights) toCommon() *sdk.RecipientWithRights {
	if s == nil {
		return nil
	}
	return &sdk.RecipientWithRights{
		Id:     s.RecipientId,
		Rights: s.Rights.toCommon(),
	}
}

type RecipientsWithRightsArray struct {
	items []*sdk.RecipientWithRights
}

func recipientsWithRightsFromCommon(s *sdk.RecipientWithRights) *RecipientWithRights {
	if s == nil {
		return nil
	}
	return &RecipientWithRights{
		RecipientId: s.Id,
		Rights:      recipientRightsFromCommon(s.Rights),
	}
}

func (array *RecipientsWithRightsArray) Add(s *RecipientWithRights) *RecipientsWithRightsArray {
	array.items = append(array.items, s.toCommon())
	return array
}
func (array *RecipientsWithRightsArray) Get(i int) *RecipientWithRights {
	return recipientsWithRightsFromCommon(array.items[i])
}
func (array *RecipientsWithRightsArray) Size() int {
	return len(array.items)
}
func (array *RecipientsWithRightsArray) getSlice() []*sdk.RecipientWithRights {
	return array.items
}

type TmrAccessesRetrievalFilters struct {
	CreatedById string
	TmrAccessId string
}

func (s *TmrAccessesRetrievalFilters) toCommon() *sdk.TmrAccessesRetrievalFilters {
	if s == nil {
		return nil
	}
	return &sdk.TmrAccessesRetrievalFilters{
		CreatedById: s.CreatedById,
		TmrAccessId: s.TmrAccessId,
	}
}

type TmrAccessesConvertFilters struct {
	SessionId   string
	CreatedById string
	TmrAccessId string
}

func (s *TmrAccessesConvertFilters) toCommon() *sdk.TmrAccessesConvertFilters {
	if s == nil {
		return nil
	}
	return &sdk.TmrAccessesConvertFilters{
		SessionId:   s.SessionId,
		CreatedById: s.CreatedById,
		TmrAccessId: s.TmrAccessId,
	}
}

type ConvertTmrAccessesResponse struct {
	Status    string
	Converted *StringArray
	Errored   int
	Succeeded int
}

func convertTmrAccessesResponseFromCommon(s *sdk.ConvertTmrAccessesResponse) *ConvertTmrAccessesResponse {
	if s == nil {
		return nil
	}

	return &ConvertTmrAccessesResponse{
		Status:    s.Status,
		Converted: sliceToStringArray(s.Converted),
		Errored:   len(s.Errored),
		Succeeded: len(s.Succeeded),
	}
}

type TmrRecipientWithRights struct {
	AuthFactor        *AuthFactor
	Rights            *RecipientRights
	OverEncryptionKey []byte
}

func (s *TmrRecipientWithRights) toCommon() *sdk.TmrRecipientWithRights {
	if s == nil {
		return nil
	}
	return &sdk.TmrRecipientWithRights{
		AuthFactor:        s.AuthFactor.toCommon(),
		Rights:            s.Rights.toCommon(),
		OverEncryptionKey: s.OverEncryptionKey,
	}
}

type TmrRecipientWithRightsArray struct {
	items []*sdk.TmrRecipientWithRights
}

func tmrRecipientWithRightsFromCommon(commonR *sdk.TmrRecipientWithRights) *TmrRecipientWithRights {
	if commonR == nil {
		return nil
	}
	return &TmrRecipientWithRights{
		AuthFactor:        &AuthFactor{Type: commonR.AuthFactor.Type, Value: commonR.AuthFactor.Value},
		Rights:            recipientRightsFromCommon(commonR.Rights),
		OverEncryptionKey: commonR.OverEncryptionKey,
	}
}

func (array *TmrRecipientWithRightsArray) Add(s *TmrRecipientWithRights) *TmrRecipientWithRightsArray {
	array.items = append(array.items, s.toCommon())
	return array
}
func (array *TmrRecipientWithRightsArray) Get(i int) *TmrRecipientWithRights {
	return tmrRecipientWithRightsFromCommon(array.items[i])
}
func (array *TmrRecipientWithRightsArray) Size() int {
	return len(array.items)
}
func (array *TmrRecipientWithRightsArray) getSlice() []*sdk.TmrRecipientWithRights {
	if array == nil {
		return nil
	}
	return array.items
}

type MobileEncryptionSessionArray struct {
	items []*sdk.EncryptionSession
}

func (array *MobileEncryptionSessionArray) Add(mes *MobileEncryptionSession) *MobileEncryptionSessionArray {
	array.items = append(array.items, mes.es)
	return array
}
func (array *MobileEncryptionSessionArray) Get(i int) *MobileEncryptionSession {
	return mobileEncryptionSessionFromCommon(array.items[i])
}
func (array *MobileEncryptionSessionArray) Size() int {
	return len(array.items)
}
func (array *MobileEncryptionSessionArray) getSlice() []*sdk.EncryptionSession {
	if array == nil {
		return nil
	}
	return array.items
}

func mobileEncryptionSessionArrayFromCommon(array []*sdk.EncryptionSession) *MobileEncryptionSessionArray {
	return &MobileEncryptionSessionArray{items: array}
}

type GroupTMRTemporaryKey struct {
	KeyId          string
	GroupId        string
	Created        int64
	IsAdmin        bool
	CreatedById    string
	AuthFactorType string
}

func groupTMRTemporaryKeyFromCommon(s *sdk.GroupTMRTemporaryKey) *GroupTMRTemporaryKey {
	if s == nil {
		return nil
	}
	return &GroupTMRTemporaryKey{
		KeyId:          s.Id,
		GroupId:        s.GroupId,
		Created:        s.Created.Unix(),
		IsAdmin:        s.IsAdmin,
		CreatedById:    s.CreatedById,
		AuthFactorType: s.AuthFactorType,
	}
}

type GroupTMRTemporaryKeyArray struct {
	gTMRTK []*sdk.GroupTMRTemporaryKey
}

func (gTMRTKArray *GroupTMRTemporaryKeyArray) Add(gTMRTK *sdk.GroupTMRTemporaryKey) *GroupTMRTemporaryKeyArray {
	gTMRTKArray.gTMRTK = append(gTMRTKArray.gTMRTK, gTMRTK)
	return gTMRTKArray
}
func (gTMRTKArray *GroupTMRTemporaryKeyArray) Get(i int) *GroupTMRTemporaryKey {
	return groupTMRTemporaryKeyFromCommon(gTMRTKArray.gTMRTK[i])
}
func (gTMRTKArray *GroupTMRTemporaryKeyArray) Size() int {
	return len(gTMRTKArray.gTMRTK)
}

type ListedGroupTMRTemporaryKeys struct {
	NbPage int
	Keys   *GroupTMRTemporaryKeyArray
}

func groupListTMRTemporaryKeyFromCommon(nativeR *sdk.ListedGroupTMRTemporaryKeys) *ListedGroupTMRTemporaryKeys {
	if nativeR == nil {
		return nil
	}
	mobileKeys := &GroupTMRTemporaryKeyArray{}
	for _, k := range nativeR.Keys {
		mobileKeys.Add(k)
	}

	return &ListedGroupTMRTemporaryKeys{NbPage: nativeR.NbPage, Keys: mobileKeys}
}

type SearchGroupTMRTemporaryKeysOpts struct {
	GroupId string
	Page    int
	All     bool
}

func (s *SearchGroupTMRTemporaryKeysOpts) toCommon() *sdk.SearchGroupTMRTemporaryKeysOpts {
	if s == nil {
		return nil
	}
	return &sdk.SearchGroupTMRTemporaryKeysOpts{
		GroupId: s.GroupId,
		Page:    s.Page,
		All:     s.All,
	}
}

type AuthFactor struct {
	Type  string `json:"type"` // 'EM' | 'SMS' no enum concept in GO, we should use a setter to ensure the value
	Value string `json:"value"`
}

func (mAF *AuthFactor) toCommon() *common_models.AuthFactor {
	return &common_models.AuthFactor{Type: mAF.Type, Value: mAF.Value}
}

func authFactorFromCommon(s *common_models.AuthFactor) *AuthFactor {
	return &AuthFactor{
		Type:  s.Type,
		Value: s.Value,
	}
}

type AuthFactorArray struct {
	items []*common_models.AuthFactor
}

func (array *AuthFactorArray) Add(s *AuthFactor) *AuthFactorArray {
	array.items = append(array.items, s.toCommon())
	return array
}
func (array *AuthFactorArray) Get(i int) *AuthFactor {
	return authFactorFromCommon(array.items[i])
}
func (array *AuthFactorArray) Size() int {
	return len(array.items)
}
func (array *AuthFactorArray) getSlice() []*common_models.AuthFactor {
	if array == nil {
		return nil
	}
	return array.items
}

type RecipientsList struct {
	SealdRecipients []*sdk.SealdRecipient
	TmrAccesses     []*sdk.TmrAccess
	ProxySessions   []*sdk.ProxySession
	SymEncKeys      []*sdk.SymEncKey
}

func (rList *RecipientsList) GetSealdRecipient(i int) *SealdRecipient {
	return sealdRecipientFromCommon(rList.SealdRecipients[i])
}
func (rList *RecipientsList) GetTmrAccess(i int) *TmrAccess {
	return tmrAccessFromCommon(rList.TmrAccesses[i])
}
func (rList *RecipientsList) GetProxySession(i int) *ProxySession {
	return proxySessionFromCommon(rList.ProxySessions[i])
}
func (rList *RecipientsList) GetSymEncKey(i int) *SymEncKey {
	return symEncKeyFromCommon(rList.SymEncKeys[i])
}

func (rList *RecipientsList) SealdRecipientsSize() int {
	return len(rList.SealdRecipients)
}
func (rList *RecipientsList) TmrAccessesSize() int {
	return len(rList.TmrAccesses)
}
func (rList *RecipientsList) ProxySessionsSize() int {
	return len(rList.ProxySessions)
}
func (rList *RecipientsList) SymEncKeysSize() int {
	return len(rList.SymEncKeys)
}

type SealdRecipient struct {
	SealdId   string
	AddedById string
	ReadFirst int64
	ReadLast  int64
	ReadTime  int
	Rights    *RecipientRights
}

func sealdRecipientFromCommon(nativeR *sdk.SealdRecipient) *SealdRecipient {
	sR := &SealdRecipient{
		SealdId:   nativeR.SealdId,
		AddedById: nativeR.AddedById,
		ReadTime:  nativeR.ReadTime,
		Rights:    recipientRightsFromCommon(nativeR.Rights),
	}
	if nativeR.ReadFirst != nil {
		sR.ReadFirst = nativeR.ReadFirst.Unix()
	}
	if nativeR.ReadLast != nil {
		sR.ReadLast = nativeR.ReadLast.Unix()
	}
	return sR
}

type TmrAccess struct {
	TmrAccessId    string
	Created        int64
	AuthFactorType string
	Rights         *RecipientRights
}

func tmrAccessFromCommon(nTmrAccess *sdk.TmrAccess) *TmrAccess {
	tA := &TmrAccess{
		TmrAccessId:    nTmrAccess.Id,
		AuthFactorType: nTmrAccess.AuthFactorType,
		Rights:         recipientRightsFromCommon(nTmrAccess.Rights),
	}
	if nTmrAccess.Created != nil {
		tA.Created = nTmrAccess.Created.Unix()
	}
	return tA
}

type ProxySession struct {
	Created        int64
	SessionId      string
	ProxySessionId string
	Rights         *RecipientRights
}

func proxySessionFromCommon(nProxySession *sdk.ProxySession) *ProxySession {
	pS := &ProxySession{
		SessionId:      nProxySession.SessionId,
		ProxySessionId: nProxySession.ProxySessionId,
		Rights:         recipientRightsFromCommon(nProxySession.Rights),
	}
	if nProxySession.Created != nil {
		pS.Created = nProxySession.Created.Unix()
	}
	return pS
}

type SymEncKey struct {
	SymEncKeyId string
	Rights      *RecipientRights
}

func symEncKeyFromCommon(nativeR *sdk.SymEncKey) *SymEncKey {
	return &SymEncKey{
		SymEncKeyId: nativeR.SymEncKeyId,
		Rights:      recipientRightsFromCommon(nativeR.Rights),
	}
}

func recipientsListFromCommon(nativeList *sdk.RecipientsList) *RecipientsList {
	return &RecipientsList{
		SealdRecipients: nativeList.SealdRecipients,
		TmrAccesses:     nativeList.TmrAccesses,
		ProxySessions:   nativeList.ProxySessions,
		SymEncKeys:      nativeList.SymEncKeys,
	}
}
