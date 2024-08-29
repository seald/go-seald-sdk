package common_models

type EncryptedFileHeader struct {
	Version   string `bson:"v"`
	MessageId string `bson:"mid"`
}

// ClearFile represents a decrypted file.
type ClearFile struct {
	// Filename is the filename of the decrypted file.
	Filename string
	// SessionId is the ID of the EncryptionSession to which this file belongs.
	SessionId string
	// FileContent is the content of the decrypted file.
	FileContent []byte
}

type ClearPath struct {
	Filename  string
	SessionId string
	Path      string
}

type AuthFactor struct {
	Type  string `json:"type"` // 'EM' | 'SMS' no enum concept in GO, we should use a setter to ensure the value
	Value string `json:"value"`
}

type ConnectorState string

const (
	ConnectorStatePending   ConnectorState = "PE"
	ConnectorStateValidated ConnectorState = "VO"
	ConnectorStateRevoked   ConnectorState = "RE"
	ConnectorStateRemoved   ConnectorState = "RM"
)

type ConnectorType string

const (
	ConnectorTypeEmail   ConnectorType = "EM"
	ConnectorTypeApp     ConnectorType = "AP"
	ConnectorTypeSealdId ConnectorType = "BE"
)

type Connector struct { // Simplified model of connector
	SealdId string         `json:"seald_id"`
	Type    ConnectorType  `json:"type"` // 'EM' | 'AP'
	Value   string         `json:"value"`
	Id      string         `json:"id"`
	State   ConnectorState `json:"state"`
	//KeyId   string    `json:"key"`
	//Created time.Time `json:"created"`
	//Updated time.Time `json:"updated"`
}
