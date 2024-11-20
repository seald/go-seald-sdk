package sdk

import (
	"encoding/base64"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/sdk/sigchain"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"strings"
	"sync"
	"time"
)

var (
	// ErrorInvalidConnectorType is returned when trying to get the indexation key of a connector with an invalid type.
	ErrorInvalidConnectorType = utils.NewSealdError("INVALID_CONNECTOR_TYPE", "invalid connector type")
	// ErrorMemberNotInGroup is returned when searching if a user is a group admin, but the user is not a group member.
	ErrorMemberNotInGroup = utils.NewSealdError("MEMBER_NOT_IN_GROUP", "user is not a group member")
	// ErrorSigchainIntegritySigchainMissingDevice is returned when the sigchain does not know a device that is in the database
	ErrorSigchainIntegritySigchainMissingDevice = utils.NewSealdError("SIGCHAIN_INTEGRITY_SIGCHAIN_MISSING_DEVICE", "")
	// ErrorSigchainIntegrityDeviceRevoked is returned when a device is revoked in the sigchain but not the database
	ErrorSigchainIntegrityDeviceRevoked = utils.NewSealdError("SIGCHAIN_INTEGRITY_DEVICE_REVOKED", "")
	// ErrorSigchainIntegrityEncryptionKeyHash is returned when the EncryptionKey's hash in the database does not match the one in the sigchain
	ErrorSigchainIntegrityEncryptionKeyHash = utils.NewSealdError("SIGCHAIN_INTEGRITY_ENCRYPTION_KEY_HASH", "")
	// ErrorSigchainIntegritySigningKeyHash is returned when the SigningKey's hash in the database does not match the one in the sigchain
	ErrorSigchainIntegritySigningKeyHash = utils.NewSealdError("SIGCHAIN_INTEGRITY_SIGNING_KEY_HASH", "")
	// ErrorSigchainIntegrityDbMissingDevice is returned when the database does not know a device that is in the sigchain
	ErrorSigchainIntegrityDbMissingDevice = utils.NewSealdError("SIGCHAIN_INTEGRITY_DB_MISSING_DEVICE", "")
)

type privateDevice interface {
	getEncryptionKeys() []*asymkey.PrivateKey
}

type currentDeviceStorage struct { // no need for lock here, as there is no map
	currentDevice *currentDevice
}

type currentDevice struct {
	UserId                   string                `json:"userId"`
	DeviceId                 string                `json:"deviceId"`
	SigningPrivateKey        *asymkey.PrivateKey   `json:"signingPrivateKey"`
	EncryptionPrivateKey     *asymkey.PrivateKey   `json:"encryptionPrivateKey"`
	OldSigningPrivateKeys    []*asymkey.PrivateKey `json:"oldSigningPrivateKeys"`
	OldEncryptionPrivateKeys []*asymkey.PrivateKey `json:"oldEncryptionPrivateKeys"`
	DeviceExpires            *time.Time            `json:"deviceExpires"`
}

func (device currentDevice) getEncryptionKeys() []*asymkey.PrivateKey {
	var result []*asymkey.PrivateKey
	result = append(result, device.EncryptionPrivateKey)
	result = append(result, device.OldEncryptionPrivateKeys...)
	return result
}

func (device *currentDeviceStorage) get() currentDevice {
	return *device.currentDevice
}

func (device *currentDeviceStorage) set(currentDevice currentDevice) {
	device.currentDevice = &currentDevice
}

type connectorsStorage struct {
	connectors map[string]common_models.Connector
	lock       sync.RWMutex
}

func getConnectorIndexKey(value string, connectorType common_models.ConnectorType) (string, error) {
	if connectorType == "EM" {
		return string(connectorType) + "/" + strings.ToLower(value), nil
	} else if connectorType == "AP" {
		return string(connectorType) + "/" + value, nil
	} else {
		return "", tracerr.Wrap(ErrorInvalidConnectorType)
	}
}

func (connectorsStorage *connectorsStorage) set(c common_models.Connector) error {
	connectorName, err := getConnectorIndexKey(c.Value, c.Type)
	if err != nil {
		return err
	}
	connectorsStorage.lock.Lock()
	connectorsStorage.connectors[connectorName] = c
	connectorsStorage.lock.Unlock()
	return nil
}

func (connectorsStorage *connectorsStorage) remove(c common_models.Connector) error {
	connectorName, err := getConnectorIndexKey(c.Value, c.Type)
	if err != nil {
		return err
	}
	connectorsStorage.lock.Lock()
	delete(connectorsStorage.connectors, connectorName)
	connectorsStorage.lock.Unlock()
	return nil
}

func (connectorsStorage *connectorsStorage) getByValue(value string, connectorType common_models.ConnectorType) (*common_models.Connector, error) {
	connectorName, err := getConnectorIndexKey(value, connectorType)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	connectorsStorage.lock.RLock()
	defer connectorsStorage.lock.RUnlock()
	c, ok := connectorsStorage.connectors[connectorName]
	if ok {
		return &c, nil
	} else {
		return nil, nil
	}
}

func (connectorsStorage *connectorsStorage) getFromSealdId(sealdId string) []common_models.Connector {
	var matchingConnectors []common_models.Connector
	connectorsStorage.lock.RLock()
	defer connectorsStorage.lock.RUnlock()
	for _, connector := range connectorsStorage.connectors {
		if connector.SealdId == sealdId {
			matchingConnectors = append(matchingConnectors, connector)
		}
	}
	return matchingConnectors
}

func (connectorsStorage *connectorsStorage) all() map[string]common_models.Connector {
	connectorsStorage.lock.RLock()
	defer connectorsStorage.lock.RUnlock()
	return connectorsStorage.connectors
}

type contactsStorage struct {
	contacts map[string]contact
	lock     sync.RWMutex
}

func (contactsStorage *contactsStorage) get(id string) *contact {
	contactsStorage.lock.RLock()
	defer contactsStorage.lock.RUnlock()
	contact, ok := contactsStorage.contacts[id]
	if ok {
		return &contact
	} else {
		return nil
	}
}

func (contactsStorage *contactsStorage) set(contact contact) {
	contactsStorage.lock.Lock()
	contactsStorage.contacts[contact.Id] = contact
	contactsStorage.lock.Unlock()
}

func (contactsStorage *contactsStorage) delete(id string) {
	contactsStorage.lock.Lock()
	delete(contactsStorage.contacts, id)
	contactsStorage.lock.Unlock()
}

func (contactsStorage *contactsStorage) all() map[string]contact {
	contactsStorage.lock.RLock()
	defer contactsStorage.lock.RUnlock()
	return contactsStorage.contacts
}

// contact represents a Seald user.
type contact struct {
	Id       string            `json:"id"`
	IsGroup  bool              `json:"isGroup"`
	Sigchain sigchain.Sigchain `json:"sigchain"`
	Devices  []*device         `json:"devices"`
}

func (contact *contact) getDevice(id string) *device {
	for _, device := range contact.Devices {
		if device.Id == id {
			return device
		}
	}
	return nil
}

type device struct {
	Id            string             `json:"id"`
	SigningKey    *asymkey.PublicKey `json:"signingKey"`
	EncryptionKey *asymkey.PublicKey `json:"encryptionKey"`
}

type groupMember struct {
	Id      string `json:"id"`
	IsAdmin bool   `json:"isAdmin"`
}

type group struct {
	Id            string        `json:"id"`
	DeviceId      string        `json:"deviceId"`
	DeviceExpires time.Time     `json:"deviceExpires"`
	CurrentKey    groupKey      `json:"currentKey"`
	OldKeys       []groupKey    `json:"oldKeys"`
	Members       []groupMember `json:"members"`
}

func (group group) isMember(userId string) bool {
	for _, member := range group.Members {
		if member.Id == userId {
			return true
		}
	}
	return false
}

func (group group) isAdmin(userId string) (bool, error) {
	for _, member := range group.Members {
		if member.Id == userId {
			return member.IsAdmin, nil
		}
	}
	return false, tracerr.Wrap(ErrorMemberNotInGroup)
}

type groupKey struct {
	MessageId            string              `json:"messageId"`
	SigningPrivateKey    *asymkey.PrivateKey `json:"signingPrivateKey"`
	EncryptionPrivateKey *asymkey.PrivateKey `json:"encryptionPrivateKey"`
}

func (group group) getEncryptionKeys() []*asymkey.PrivateKey {
	var result []*asymkey.PrivateKey
	result = append(result, group.CurrentKey.EncryptionPrivateKey)
	if group.OldKeys != nil {
		result = append(result, utils.SliceMap(group.OldKeys, func(groupKey groupKey) *asymkey.PrivateKey { return groupKey.EncryptionPrivateKey })...)
	}
	return result
}

type groupsStorage struct {
	groups map[string]group
	lock   sync.RWMutex
}

func (groupsStorage *groupsStorage) get(id string) *group {
	groupsStorage.lock.RLock()
	defer groupsStorage.lock.RUnlock()
	group, ok := groupsStorage.groups[id]
	if ok {
		return &group
	} else {
		return nil
	}
}

func (groupsStorage *groupsStorage) set(group group) {
	groupsStorage.lock.Lock()
	defer groupsStorage.lock.Unlock()
	groupsStorage.groups[group.Id] = group
}

func (groupsStorage *groupsStorage) delete(groupId string) {
	groupsStorage.lock.Lock()
	defer groupsStorage.lock.Unlock()
	delete(groupsStorage.groups, groupId)
}

// EncryptionSessionRetrievalFlow represents the way the session was retrieved : as a direct recipient, as member of a group, or through a proxy session
type EncryptionSessionRetrievalFlow int

const (
	EncryptionSessionRetrievalCreated      EncryptionSessionRetrievalFlow = iota // 0 - The session was created locally.
	EncryptionSessionRetrievalDirect                                             // 1 - The session was retrieved as a direct recipient.
	EncryptionSessionRetrievalViaGroup                                           // 2 - The session was retrieved as a member of a group.
	EncryptionSessionRetrievalViaProxy                                           // 3 - The session was retrieved through a proxy session.
	EncryptionSessionRetrievalViaTmrAccess                                       // 4 - The session was retrieved through a TMR access
)

// EncryptionSessionRetrievalDetails represents the details of how an Encryption Session was retrieved.
type EncryptionSessionRetrievalDetails struct {
	// Flow represents the way the session was retrieved : as a direct recipient, as member of a group, or through a proxy session.
	Flow EncryptionSessionRetrievalFlow `json:"flow"`
	// GroupId gives, if the session was retrieved as member of a group, the ID of the group in question.
	GroupId string `json:"groupId"`
	// ProxySessionId gives, if the session was retrieved through a proxy session, the ID of this proxy session.
	ProxySessionId string `json:"proxySessionId"`
	// FromCache indicates if this session was retrieved from the cache.
	FromCache bool `json:"-"`
}

type encryptionSessionCacheEntry struct {
	B64SerializedSymKey string                            `json:"b64SerializedSymKey"`
	SerializationDate   time.Time                         `json:"serializationDate"`
	RetrievalDetails    EncryptionSessionRetrievalDetails `json:"retrievalDetails"`
}

type encryptionSessionCache struct {
	cacheTTL                  time.Duration
	cacheCleanupInterval      time.Duration
	cacheCleanupIntervalTimer *time.Timer
	encryptionSessions        map[string]encryptionSessionCacheEntry
	lock                      sync.RWMutex
}

func (esc *encryptionSessionCache) setTTL(t time.Duration) {
	esc.cacheTTL = t
}

func (esc *encryptionSessionCache) startCleanupInterval(t time.Duration) {
	esc.cacheCleanupInterval = t
	esc.stopCleanupInterval()
	go esc.cleanupInterval()
}

func (esc *encryptionSessionCache) cleanupInterval() {
	if esc.cacheCleanupInterval < 0 { // if interval is < 0, it means it is disabled : no interval to enable
		return
	}
	esc.cacheCleanupIntervalTimer = time.AfterFunc(esc.cacheCleanupInterval, func() {
		esc.clean()
		esc.cleanupInterval()
	})
}

func (esc *encryptionSessionCache) stopCleanupInterval() {
	if esc.cacheCleanupIntervalTimer != nil {
		esc.cacheCleanupIntervalTimer.Stop()
		esc.cacheCleanupIntervalTimer = nil
	}
}

func (esc *encryptionSessionCache) Set(sessionId string, sessionSymKey symmetric_key.SymKey, details EncryptionSessionRetrievalDetails) {
	if esc.cacheTTL == 0 { // if cacheTTL is 0, cache is disabled: don't bother to store anything
		return
	}
	b64SerializedSymKey := base64.StdEncoding.EncodeToString(sessionSymKey.Encode())
	session := encryptionSessionCacheEntry{B64SerializedSymKey: b64SerializedSymKey, SerializationDate: time.Now(), RetrievalDetails: details}
	esc.lock.Lock()
	defer esc.lock.Unlock()
	esc.encryptionSessions[sessionId] = session
}

type encryptionSessionFromCache struct {
	Symkey           *symmetric_key.SymKey
	RetrievalDetails EncryptionSessionRetrievalDetails
}

func (esc *encryptionSessionCache) get(sessionId string) (*encryptionSessionFromCache, error) {
	if esc.cacheTTL == 0 { // if cacheTTL is 0, cache is disabled: don't bother to get anything
		return nil, nil
	}
	esc.lock.RLock()
	serializedSession, ok := esc.encryptionSessions[sessionId]
	esc.lock.RUnlock()
	if ok {
		if esc.cacheTTL < 0 || time.Now().Before(serializedSession.SerializationDate.Add(esc.cacheTTL)) {
			symKeyBuff, err := base64.StdEncoding.DecodeString(serializedSession.B64SerializedSymKey)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			symKey, err := symmetric_key.Decode(symKeyBuff)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			retrievalDetails := serializedSession.RetrievalDetails
			retrievalDetails.FromCache = true
			return &encryptionSessionFromCache{Symkey: &symKey, RetrievalDetails: retrievalDetails}, nil
		} else {
			esc.delete(sessionId)
			return nil, nil
		}
	}
	return nil, nil
}

func (esc *encryptionSessionCache) delete(sessionId string) {
	esc.lock.Lock()
	delete(esc.encryptionSessions, sessionId)
	esc.lock.Unlock()
}

func (esc *encryptionSessionCache) clean() {
	if esc.cacheTTL < 0 { // if cacheTTL is negative, cache duration is infinite : not necessary to clean
		return
	}
	esc.lock.Lock()
	for sessionId, entries := range esc.encryptionSessions {
		if esc.cacheTTL == 0 || time.Now().After(entries.SerializationDate.Add(esc.cacheTTL)) {
			delete(esc.encryptionSessions, sessionId)
		}
	}
	esc.lock.Unlock()
}

func (esc *encryptionSessionCache) len() int {
	esc.lock.RLock()
	defer esc.lock.RUnlock()
	return len(esc.encryptionSessions)
}

func checkKeyringMatchesSigChain(result *sigchain.CheckSigchainTransactionsResult, keyring []*device) error {
	for _, device := range keyring {
		sigchainDevice, exists := result.KnownKeys[device.Id]
		if !exists {
			return tracerr.Wrap(ErrorSigchainIntegritySigchainMissingDevice)
		}
		if sigchainDevice.Revoked {
			return tracerr.Wrap(ErrorSigchainIntegrityDeviceRevoked)
		}
		if sigchainDevice.EncryptionKeyHash != device.EncryptionKey.GetHash() {
			return tracerr.Wrap(ErrorSigchainIntegrityEncryptionKeyHash)
		}
		if sigchainDevice.SigningKeyHash != device.SigningKey.GetHash() {
			return tracerr.Wrap(ErrorSigchainIntegritySigningKeyHash)
		}

	}
	for id, key := range result.KnownKeys {
		if !key.Revoked {
			found := false
			for _, device := range keyring {
				if device.Id == id {
					found = true
					break
				}
			}
			if !found {
				return tracerr.Wrap(ErrorSigchainIntegrityDbMissingDevice)
			}
		}
	}
	return nil
}

type RecipientRights struct {
	Read    bool `json:"read"`
	Forward bool `json:"forward"`
	Revoke  bool `json:"revoke"`
}

type RecipientWithRights struct {
	Id     string
	Rights *RecipientRights
}

func getRecipientIdsAndMap(recipientsWithRights []*RecipientWithRights) ([]string, map[string]*RecipientRights) {
	var recipientsIds []string
	recipientsMap := make(map[string]*RecipientRights)
	for _, recipient := range recipientsWithRights {
		recipientsIds = append(recipientsIds, recipient.Id)
		if recipient.Rights != nil {
			recipientsMap[recipient.Id] = recipient.Rights
		}
	}

	return recipientsIds, recipientsMap
}
