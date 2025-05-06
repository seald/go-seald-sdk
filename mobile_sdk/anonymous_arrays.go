package mobile_sdk

import (
	"github.com/seald/go-seald-sdk/anonymous_sdk"
)

type AnonymousTmrRecipient struct {
	AuthFactor           *AuthFactor
	RawOverEncryptionKey []byte
}

func (s *AnonymousTmrRecipient) toCommon() *anonymous_sdk.TMRRecipient {
	if s == nil {
		return nil
	}
	return &anonymous_sdk.TMRRecipient{
		AuthFactor:           s.AuthFactor.toCommon(),
		RawOverEncryptionKey: s.RawOverEncryptionKey,
	}
}

type AnonymousTmrRecipientArray struct {
	items []*anonymous_sdk.TMRRecipient
}

func anonymousTmrRecipientFromCommon(commonR *anonymous_sdk.TMRRecipient) *AnonymousTmrRecipient {
	if commonR == nil {
		return nil
	}
	return &AnonymousTmrRecipient{
		AuthFactor:           &AuthFactor{Type: commonR.AuthFactor.Type, Value: commonR.AuthFactor.Value},
		RawOverEncryptionKey: commonR.RawOverEncryptionKey,
	}
}

func (array *AnonymousTmrRecipientArray) Add(s *AnonymousTmrRecipient) *AnonymousTmrRecipientArray {
	array.items = append(array.items, s.toCommon())
	return array
}
func (array *AnonymousTmrRecipientArray) Get(i int) *AnonymousTmrRecipient {
	return anonymousTmrRecipientFromCommon(array.items[i])
}
func (array *AnonymousTmrRecipientArray) Size() int {
	return len(array.items)
}
func (array *AnonymousTmrRecipientArray) getSlice() []*anonymous_sdk.TMRRecipient {
	return array.items
}
