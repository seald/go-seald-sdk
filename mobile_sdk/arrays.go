package mobile_sdk

import (
	"go-seald-sdk/common_models"
	"go-seald-sdk/sdk"
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
	return array.items
}

func mobileEncryptionSessionArrayFromCommon(array []*sdk.EncryptionSession) *MobileEncryptionSessionArray {
	return &MobileEncryptionSessionArray{items: array}
}
