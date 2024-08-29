package sigchain

type Sigchain struct {
	Blocks []*Block
}

func (sigchain *Sigchain) GetLastBlock() *Block {
	return sigchain.Blocks[len(sigchain.Blocks)-1]
}

type Block struct {
	Transaction Transaction `json:"transaction"`
	Extras      Extras      `json:"extras"`
	Signature   Signature   `json:"signature"`
}

type Extras struct {
	PublicKeys []string `json:"pubkeys"`
}

type Transaction struct {
	Signer       Signer    `json:"signer"`
	Position     int       `json:"position"`
	PreviousHash string    `json:"previous_hash"`
	CreatedAt    int64     `json:"created_at"`
	ExpireAt     int64     `json:"expire_at"`
	Operation    Operation `json:"operation"`
}

type Operation struct {
	Type   Type            `json:"type"`
	Device *SigchainDevice `json:"device,omitempty"` // pointer because it can be nil
	// Members must be omitted for non-members related transaction. But it must be present with an empty array to remove a group.
	Members *[]string `json:"members,omitempty"` // nil pointer => key omitted. pointer to empty allocated array => []
}

type Type string

const SIGCHAIN_OPERATION_CREATE Type = "creation"
const SIGCHAIN_OPERATION_REVOKE Type = "revocation"
const SIGCHAIN_OPERATION_RENEWAL Type = "renewal"
const SIGCHAIN_OPERATION_MEMBERS Type = "members"
const SIGCHAIN_OPERATION_SERVER_REMOVE_MEMBERS Type = "server-remove-members"

type Signer struct {
	User     string `json:"user"`
	DeviceId string `json:"device_id"`
}

type SigchainDevice struct {
	Id                      string `json:"id"`
	EncryptionPublicKeyHash string `json:"encryption_pubkey_hash"`
	SigningPublicKeyHash    string `json:"signing_pubkey_hash"`
}

type Signature struct {
	Protocol        string `json:"protocol"`
	Hash            string `json:"hash"`
	SignatureString string `json:"signature"`
}
