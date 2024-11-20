package sigchain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/gibson042/canonicaljson-go"
	"github.com/seald/go-seald-sdk/asymkey"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"time"
)

var (
	InvalidSigchainTransactionHashMalformed          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_HASH_MALFORMED", "")
	InvalidSigchainTransactionInvalidHash            = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_INVALID_HASH", "")
	InvalidSigchainTransactionInvalidProtocol        = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_INVALID_PROTOCOL", "")
	InvalidSigchainTransactionSignatureMalformed     = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SIGNATURE_MALFORMED", "")
	InvalidSigchainTransactionWrongPosition          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_WRONG_POSITION", "")
	InvalidSigchainTransactionWrongPreviousHash      = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_WRONG_PREVIOUS_HASH", "")
	InvalidSigchainTransactionCreatedOrder           = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_CREATED_ORDER", "")
	InvalidSigchainTransactionFirstOperationType     = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_FIRST_OPERATION_TYPE", "")
	InvalidSigchainTransactionFirstOperationAutosign = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_FIRST_OPERATION_AUTOSIGN", "")
	InvalidSigchainTransactionCreatedInFuture        = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_CREATED_IN_FUTURE", "")
	InvalidSigchainTransactionCreateSelf             = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_CREATE_SELF", "")
	InvalidSigchainTransactionCreateExisting         = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_CREATE_EXISTING", "")
	InvalidSigchainTransactionCreateSigner           = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_CREATE_SIGNER", "")
	InvalidSigchainTransactionExpireBeforeCreate     = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_EXPIRE_BEFORE_CREATE", "")
	InvalidSigchainTransactionExpireTooLateCreate    = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_EXPIRE_TOO_LATE_CREATE", "")
	InvalidSigchainTransactionBadKeyCreate2          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_BAD_KEY_CREATE_2", "")
	InvalidSigchainTransactionBadKeyCreate1          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_BAD_KEY_CREATE_1", "")
	InvalidSigchainTransactionMissingKeyCreate       = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_MISSING_KEY_CREATE", "")
	InvalidSigchainTransactionRenewSelf              = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_RENEW_SELF", "")
	InvalidSigchainTransactionRenewNotExisting       = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_RENEW_NOT_EXISTING", "")
	InvalidSigchainTransactionRenewSameKey           = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_RENEW_SAME_KEY", "")
	InvalidSigchainTransactionExpireBeforeRenew      = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_EXPIRE_BEFORE_RENEW", "")
	InvalidSigchainTransactionExpireTooLateRenew     = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_EXPIRE_TOO_LATE_RENEW", "")
	InvalidSigchainTransactionRevokeNotExisting      = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_REVOKE_NOT_EXISTING", "")
	InvalidSigchainTransactionRevokeAlreadyRevoked   = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_REVOKE_ALREADY_REVOKED", "")
	InvalidSigchainTransactionRevokeExpiration       = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_REVOKE_EXPIRATION", "")
	InvalidSigchainTransactionServerRemoveExpiration = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SERVER_REMOVE_EXPIRATION", "")
	InvalidSigchainTransactionServerRemoveEmpty      = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SERVER_REMOVE_EMPTY", "")
	InvalidSigchainTransactionMembers                = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_MEMBERS", "")
	InvalidSigchainTransactionMembersExpiration      = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_MEMBERS_EXPIRATION", "")
	InvalidSigchainTransactionMembersNoDevice        = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_MEMBERS_NO_DEVICE", "")
	InvalidSigchainTransactionMembersNoEncryptionKey = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_MEMBERS_NO_ENCRYPTION_KEY", "")
	InvalidSigchainTransactionMembersNoSigningKey    = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_MEMBERS_NO_SIGNING_KEY", "")
	InvalidSigchainTransactionUnknownUserToRemove    = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_UNKNOWN_USER_TO_REMOVE", "")
	InvalidSigchainTransactionSignerUnknown          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SIGNER_UNKNOWN", "")
	InvalidSigchainTransactionSignerRevoked          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SIGNER_REVOKED", "")
	InvalidSigchainTransactionSignerExpired          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SIGNER_EXPIRED", "")
	InvalidSigchainTransactionSignatureInvalid       = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SIGNATURE_INVALID", "")
	InvalidSigchainTransactionUnsignedNotRevoke      = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_UNSIGNED_NOT_REVOKE", "")
	InvalidSigchainTransactionSignedNotSelf          = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_SIGNED_NOT_SELF", "")
	InvalidSigchainTransactionBadKeyRenew2           = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_BAD_KEY_RENEW_2", "")
	InvalidSigchainTransactionBadKeyRenew1           = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_BAD_KEY_RENEW_1", "")
	InvalidSigchainTransactionMissingKeyRenew        = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_MISSING_KEY_RENEW", "")
	InvalidSigchainTransactionWrongKeyHash           = utils.NewSealdError("INVALID_SIGCHAIN_TRANSACTION_WRONG_KEY_HASH", "")
)

func (transaction *Transaction) Hash() (string, error) {
	serializedTransaction, err := canonicaljson.Marshal(transaction)
	if err != nil {
		return "", tracerr.Wrap(err)
	}

	transactionHash := sha256.New()
	transactionHash.Write(serializedTransaction)

	return hex.EncodeToString(transactionHash.Sum(nil)), nil
}

func (transaction *Transaction) Sign(key *asymkey.PrivateKey) (*Block, error) {
	transactionHash, err := transaction.Hash()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	signature, err := key.Sign([]byte(transactionHash))
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	block := Block{
		Transaction: *transaction,
		Signature: Signature{
			Hash:            transactionHash,
			Protocol:        "2",
			SignatureString: base64.StdEncoding.EncodeToString(signature),
		},
		Extras: Extras{PublicKeys: []string{key.Public().ToB64()}},
	}

	return &block, nil
}

type CreateSigchainTransactionOptions struct {
	OperationType          Type
	OperationEncryptionKey *asymkey.PublicKey
	OperationSigningKey    *asymkey.PublicKey
	OperationMembers       *[]string
	OperationDeviceId      string
	SignerDeviceId         string
	ExpireAfter            time.Duration
	CreatedAt              *time.Time
	SigningKey             *asymkey.PrivateKey
	Position               int
	PreviousHash           string
}

func CreateSigchainTransaction(options *CreateSigchainTransactionOptions) (*Block, error) {
	var createdAt time.Time
	var expireAt int64
	if options.CreatedAt == nil {
		createdAt = time.Now()
	} else {
		createdAt = *options.CreatedAt
	}
	if options.OperationType == SIGCHAIN_OPERATION_REVOKE || options.OperationType == SIGCHAIN_OPERATION_MEMBERS || options.OperationType == SIGCHAIN_OPERATION_SERVER_REMOVE_MEMBERS {
		expireAt = 0
	} else {
		if options.ExpireAfter == 0 {
			expireAt = createdAt.Add(DEVICE_DEFAULT_LIFE_TIME).Unix()
		} else {
			expireAt = createdAt.Add(options.ExpireAfter).Unix()
		}
	}
	var operation Operation

	if options.OperationType == SIGCHAIN_OPERATION_MEMBERS {
		operation = Operation{
			Type:    options.OperationType,
			Members: options.OperationMembers,
		}
	} else {
		operation = Operation{
			Type: options.OperationType,
			Device: &SigchainDevice{
				Id:                      options.OperationDeviceId,
				EncryptionPublicKeyHash: options.OperationEncryptionKey.GetHash(),
				SigningPublicKeyHash:    options.OperationSigningKey.GetHash(),
			},
		}
	}
	transaction := Transaction{
		Signer:       Signer{User: "self", DeviceId: options.SignerDeviceId},
		Position:     options.Position,
		PreviousHash: options.PreviousHash,
		CreatedAt:    createdAt.Unix(),
		ExpireAt:     expireAt,
		Operation:    operation,
	}

	transactionHashHex, err := transaction.Hash()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	signature, err := options.SigningKey.Sign([]byte(transactionHashHex))
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var extras Extras
	if options.OperationSigningKey != nil {
		extras.PublicKeys = []string{options.OperationSigningKey.ToB64()}
	} else {
		extras.PublicKeys = []string{}
	}

	block := Block{
		Transaction: transaction,
		Extras:      extras,
		Signature: Signature{
			Protocol:        "2",
			Hash:            transactionHashHex,
			SignatureString: base64.StdEncoding.EncodeToString(signature),
		},
	}

	return &block, nil
}

type Key struct {
	SigningKey        *asymkey.PublicKey
	EncryptionKeyHash string
	SigningKeyHash    string
	Revoked           bool
	ExpireAt          int64
}

type CheckSigchainTransactionsResult struct {
	KnownMembers utils.Set[string]
	KnownKeys    map[string]*Key
}

func CheckSigchainTransactions(sigchain Sigchain, strictMode bool) (*CheckSigchainTransactionsResult, error) {
	previousHash := ""
	position := 0
	previousCreated := int64(0)
	knownMembers := utils.Set[string]{}
	knownKeys := map[string]*Key{}

	for _, block := range sigchain.Blocks {
		transaction := block.Transaction
		transactionHash, err := transaction.Hash()
		if err != nil {
			return nil, tracerr.Wrap(InvalidSigchainTransactionHashMalformed)
		}

		if block.Signature.Hash != transactionHash {
			return nil, tracerr.Wrap(InvalidSigchainTransactionInvalidHash)
		}
		if block.Signature.Protocol != "2" {
			return nil, tracerr.Wrap(InvalidSigchainTransactionInvalidProtocol)
		}
		signature, err := base64.StdEncoding.DecodeString(block.Signature.SignatureString)
		if err != nil {
			return nil, tracerr.Wrap(InvalidSigchainTransactionSignatureMalformed)
		}
		if transaction.Position != position {
			return nil, tracerr.Wrap(InvalidSigchainTransactionWrongPosition)
		}
		if transaction.PreviousHash != previousHash {
			return nil, tracerr.Wrap(InvalidSigchainTransactionWrongPreviousHash)
		}
		// Server accepts a delta of 1h, so if 2 transactions are sent to beard at the exact same time, one with a timestamp 1h into the future, and one 1h into the past, the max negative difference between successive transactions is 2h
		if transaction.CreatedAt < time.Unix(previousCreated, 0).Add(-2*SIGCHAIN_MAX_CREATED_DELTA).Unix() {
			return nil, tracerr.Wrap(InvalidSigchainTransactionCreatedOrder)
		}

		if transaction.Position == 0 {
			if transaction.Operation.Type != SIGCHAIN_OPERATION_CREATE {
				return nil, tracerr.Wrap(InvalidSigchainTransactionFirstOperationType)
			}
			if transaction.Signer.DeviceId != transaction.Operation.Device.Id {
				return nil, tracerr.Wrap(InvalidSigchainTransactionFirstOperationAutosign)
			}
		}

		if transaction.CreatedAt > time.Now().Add(SIGCHAIN_MAX_CREATED_DELTA).Unix() {
			return nil, tracerr.Wrap(InvalidSigchainTransactionCreatedInFuture)
		}

		if transaction.Operation.Type == SIGCHAIN_OPERATION_CREATE {
			if transaction.Signer.User != "self" {
				return nil, tracerr.Wrap(InvalidSigchainTransactionCreateSelf)
			}
			_, exists := knownKeys[transaction.Operation.Device.Id]
			if exists {
				return nil, tracerr.Wrap(InvalidSigchainTransactionCreateExisting)
			}

			if transaction.Position > 0 && transaction.Signer.DeviceId == transaction.Operation.Device.Id {
				return nil, tracerr.Wrap(InvalidSigchainTransactionCreateSigner)
			}

			if transaction.ExpireAt < transaction.CreatedAt {
				return nil, tracerr.Wrap(InvalidSigchainTransactionExpireBeforeCreate)
			}

			if transaction.ExpireAt-transaction.CreatedAt > int64(DEVICE_MAX_LIFE_TIME.Seconds()) {
				return nil, tracerr.Wrap(InvalidSigchainTransactionExpireTooLateCreate)
			}

			var operationSigningKey *asymkey.PublicKey

			for _, publicKeyB64 := range block.Extras.PublicKeys {
				publicKeyRaw, err := base64.StdEncoding.DecodeString(publicKeyB64)
				if err != nil {
					return nil, tracerr.Wrap(InvalidSigchainTransactionBadKeyCreate2)
				}
				hash := sha256.New()
				hash.Write(publicKeyRaw)
				hash.Sum(nil)

				if transaction.Operation.Device.SigningPublicKeyHash == base64.StdEncoding.EncodeToString(hash.Sum(nil)) {
					operationSigningKey, err = asymkey.PublicKeyDecode(publicKeyRaw)
					if err != nil {
						return nil, tracerr.Wrap(InvalidSigchainTransactionBadKeyCreate1)
					}
					break
				}
			}
			if operationSigningKey == nil {
				return nil, tracerr.Wrap(InvalidSigchainTransactionMissingKeyCreate)
			}
			knownKeys[transaction.Operation.Device.Id] = &Key{
				SigningKey:        operationSigningKey,
				EncryptionKeyHash: transaction.Operation.Device.EncryptionPublicKeyHash,
				SigningKeyHash:    transaction.Operation.Device.SigningPublicKeyHash,
				Revoked:           false,
				ExpireAt:          transaction.ExpireAt,
			}
		}

		if transaction.Operation.Type == SIGCHAIN_OPERATION_RENEWAL {
			if transaction.Signer.User != "self" {
				return nil, tracerr.Wrap(InvalidSigchainTransactionRenewSelf)
			}

			_, exists := knownKeys[transaction.Operation.Device.Id]
			if !exists {
				return nil, tracerr.Wrap(InvalidSigchainTransactionRenewNotExisting)
			}

			if transaction.Signer.DeviceId != transaction.Operation.Device.Id {
				return nil, tracerr.Wrap(InvalidSigchainTransactionRenewSameKey)
			}

			if transaction.ExpireAt < transaction.CreatedAt {
				return nil, tracerr.Wrap(InvalidSigchainTransactionExpireBeforeRenew)
			}

			if transaction.ExpireAt-transaction.CreatedAt > int64(DEVICE_MAX_LIFE_TIME.Seconds()) {
				return nil, tracerr.Wrap(InvalidSigchainTransactionExpireTooLateRenew)
			}
		}

		if transaction.Operation.Type == SIGCHAIN_OPERATION_REVOKE {
			knownKey, exists := knownKeys[transaction.Operation.Device.Id]
			if !exists {
				return nil, tracerr.Wrap(InvalidSigchainTransactionRevokeNotExisting)
			}
			if knownKey.Revoked {
				return nil, tracerr.Wrap(InvalidSigchainTransactionRevokeAlreadyRevoked)
			}
			if transaction.ExpireAt != 0 {
				return nil, tracerr.Wrap(InvalidSigchainTransactionRevokeExpiration)
			}
		}
		if transaction.Operation.Type == SIGCHAIN_OPERATION_SERVER_REMOVE_MEMBERS {
			if transaction.ExpireAt != 0 {
				return nil, tracerr.Wrap(InvalidSigchainTransactionServerRemoveExpiration)
			}
			if len(*transaction.Operation.Members) == 0 {
				return nil, tracerr.Wrap(InvalidSigchainTransactionServerRemoveEmpty)
			}
		} else if transaction.Operation.Type != SIGCHAIN_OPERATION_MEMBERS && transaction.Operation.Members != nil {
			return nil, tracerr.Wrap(InvalidSigchainTransactionMembers)
		}
		if transaction.Operation.Type == SIGCHAIN_OPERATION_MEMBERS {
			if transaction.ExpireAt != 0 {
				return nil, tracerr.Wrap(InvalidSigchainTransactionMembersExpiration)
			}

			if transaction.Operation.Device != nil {
				if transaction.Operation.Device.Id != "" {
					return nil, tracerr.Wrap(InvalidSigchainTransactionMembersNoDevice)
				}

				if transaction.Operation.Device.EncryptionPublicKeyHash != "" {
					return nil, tracerr.Wrap(InvalidSigchainTransactionMembersNoEncryptionKey)
				}

				if transaction.Operation.Device.SigningPublicKeyHash != "" {
					return nil, tracerr.Wrap(InvalidSigchainTransactionMembersNoSigningKey)
				}
			}

			for _, user := range *transaction.Operation.Members {
				knownMembers.Add(user)
			}
		}

		if transaction.Operation.Type == SIGCHAIN_OPERATION_SERVER_REMOVE_MEMBERS {
			for _, userToRemove := range *transaction.Operation.Members {
				if !knownMembers.Has(userToRemove) {
					return nil, tracerr.Wrap(InvalidSigchainTransactionUnknownUserToRemove)
				} else {
					knownMembers.Remove(userToRemove)
				}
			}
		}
		if transaction.Signer.User == "self" {
			knownKey, exists := knownKeys[transaction.Signer.DeviceId]
			if !exists {
				return nil, tracerr.Wrap(InvalidSigchainTransactionSignerUnknown)
			}
			if knownKey.Revoked {
				return nil, tracerr.Wrap(InvalidSigchainTransactionSignerRevoked)
			}

			if knownKey.ExpireAt < transaction.CreatedAt && (strictMode || transaction.Operation.Type != SIGCHAIN_OPERATION_RENEWAL) {
				return nil, tracerr.Wrap(InvalidSigchainTransactionSignerExpired)
			}
			err = knownKey.SigningKey.Verify([]byte(transactionHash), signature)
			if err != nil {
				return nil, tracerr.Wrap(InvalidSigchainTransactionSignatureInvalid)
			}
		} else {
			if transaction.Operation.Type != SIGCHAIN_OPERATION_REVOKE && transaction.Operation.Type != SIGCHAIN_OPERATION_SERVER_REMOVE_MEMBERS {
				return nil, tracerr.Wrap(InvalidSigchainTransactionUnsignedNotRevoke)
			}
			if block.Signature.SignatureString != "" || block.Transaction.Signer.DeviceId != "" {
				return nil, tracerr.Wrap(InvalidSigchainTransactionSignedNotSelf)
			}
		}

		if transaction.Operation.Type == SIGCHAIN_OPERATION_REVOKE {
			knownKeys[transaction.Operation.Device.Id].Revoked = true
		}

		if transaction.Operation.Type == SIGCHAIN_OPERATION_RENEWAL {
			var operationSigningKey *asymkey.PublicKey
			for _, publicKeyB64 := range block.Extras.PublicKeys {
				publicKeyRaw, err := base64.StdEncoding.DecodeString(publicKeyB64)
				if err != nil {
					return nil, tracerr.Wrap(InvalidSigchainTransactionBadKeyRenew2)
				}
				hash := sha256.New()
				hash.Write(publicKeyRaw)
				hash.Sum(nil)

				if transaction.Operation.Device.SigningPublicKeyHash == base64.StdEncoding.EncodeToString(hash.Sum(nil)) {
					operationSigningKey, err = asymkey.PublicKeyDecode(publicKeyRaw)
					if err != nil {
						return nil, tracerr.Wrap(InvalidSigchainTransactionBadKeyRenew1)
					}
					break
				}
			}
			if operationSigningKey == nil {
				return nil, tracerr.Wrap(InvalidSigchainTransactionMissingKeyRenew)
			}

			knownKeys[transaction.Operation.Device.Id] = &Key{
				SigningKey:        operationSigningKey,
				EncryptionKeyHash: transaction.Operation.Device.EncryptionPublicKeyHash,
				SigningKeyHash:    transaction.Operation.Device.SigningPublicKeyHash,
				Revoked:           false,
				ExpireAt:          transaction.ExpireAt,
			}
		}

		if transaction.Operation.Device != nil && transaction.Operation.Device.Id != "" && (knownKeys[transaction.Operation.Device.Id].SigningKeyHash != transaction.Operation.Device.SigningPublicKeyHash) {
			return nil, tracerr.Wrap(InvalidSigchainTransactionWrongKeyHash)
		}

		previousHash = transactionHash
		position++
		previousCreated = transaction.CreatedAt
	}
	return &CheckSigchainTransactionsResult{KnownKeys: knownKeys, KnownMembers: knownMembers}, nil
}
