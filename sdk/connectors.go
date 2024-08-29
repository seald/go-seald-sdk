package sdk

import (
	"fmt"
	"github.com/ztrue/tracerr"
	"go-seald-sdk/common_models"
	"go-seald-sdk/utils"
	"net/mail"
	"strings"
)

var (
	// ErrorGetSealdIdsFromConnectorsNoConnectors is returned when passed an empty slice of connector.
	ErrorGetSealdIdsFromConnectorsNoConnectors = utils.NewSealdError("GET_SEALD_IDS_FROM_CONNECTORS_NO_CONNECTORS", "no connector to verify given")
	// ErrorGetSealdIdsUnknownConnector is returned when one connector is unknown and don't have a corresponding sealdId
	ErrorGetSealdIdsUnknownConnector = utils.NewSealdError("GET_SEALD_IDS_UNKNOWN_CONNECTORS", "no seald id found for a connector")
	// ErrorAddConnectorEmptyValue is returned when trying to add a connector with an empty string as value
	ErrorAddConnectorEmptyValue = utils.NewSealdError("ADD_CONNECTOR_EMPTY_VALUE", "connector value cannot be empty")
	// ErrorAddConnectorInvalidValueAP is returned when a connector has a type ConnectorTypeApp, but its value does not end with "@APP_ID"
	ErrorAddConnectorInvalidValueAP = utils.NewSealdError("ADD_CONNECTOR_INVALID_VALUE_AP", "value must be a valid app id")
	// ErrorAddConnectorInvalidValueEmail is returned when a connector has a type ConnectorTypeEmail, but its value is not a valid email.
	ErrorAddConnectorInvalidValueEmail = utils.NewSealdError("ADD_CONNECTOR_INVALID_VALUE_EMAIL", "value must be a valid email")
	// ErrorAddConnectorInvalidType is returned when a connector type is not ConnectorTypeEmail or ConnectorTypeApp
	ErrorAddConnectorInvalidType = utils.NewSealdError("ADD_CONNECTOR_INVALID_TYPE", "invalid connector type. Type must be \"EM\" or \"AP\"")
	// ErrorValidateConnectorInvalidChallenge is returned when trying to validate a connector without a challenge
	ErrorValidateConnectorInvalidChallenge = utils.NewSealdError("VALIDATE_CONNECTOR_INVALID_CHALLENGE", "no validation challenge given")
)

// ConnectorTypeValue is a simplified representation of a common_models.connectors for which we don't know all fields.
type ConnectorTypeValue struct {
	Type  common_models.ConnectorType `json:"type"`
	Value string                      `json:"value"`
}

// GetSealdIdsFromConnectors gets all the info for the given connectorToLookFor, updates the local cache of connectors,
// and returns a slice with the corresponding SealdIds. SealdIds are not de-duped and can appear for multiple connector values.
// If one of the connectors is not assigned to a Seald user, this will return a ErrorGetSealdIdsUnknownConnector error,
// with the details of the missing connector.
func (state *State) GetSealdIdsFromConnectors(connectorTypeValues []*ConnectorTypeValue) ([]string, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if len(connectorTypeValues) == 0 {
		return nil, tracerr.Wrap(ErrorGetSealdIdsFromConnectorsNoConnectors)
	}

	uniqueConnectors := utils.UniqueSlice(connectorTypeValues)

	var result []string
	pageSize := 10
	for _, connectorsPage := range utils.ChunkSlice[*ConnectorTypeValue](uniqueConnectors, pageSize) {
		connectorsToVerify := &verifyConnectorRequest{Connectors: connectorsPage}

		verifiedConnectors, err := autoLogin(state, state.apiClient.verifyConnector)(connectorsToVerify)
		if err != nil {
			return nil, tracerr.Wrap(err)
		}

		for _, vc := range verifiedConnectors.Results {
			if vc.SealdId != "" {
				result = append(result, vc.SealdId)
			} else {
				return nil, tracerr.Wrap(ErrorGetSealdIdsUnknownConnector.AddDetails(fmt.Sprintf("type: \"%s\", value: \"%s\"", vc.Type, vc.Value)))
			}

			// Check if we know connectors locally. If not, get full connector info and save it.
			knownConnector, err := state.storage.connectors.getByValue(vc.Value, vc.Type)
			if err != nil {
				return nil, tracerr.Wrap(err)
			}
			if knownConnector == nil || knownConnector.SealdId != vc.SealdId { // new connector || owner changed
				err = state.storage.connectors.set(*vc)
				if err != nil {
					return nil, tracerr.Wrap(err)
				}
			}
		}
	}

	err = state.saveConnectors()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	return result, nil // output is not dedupe
}

// GetConnectorsFromSealdId lists all connectors know locally for a given sealdId.
func (state *State) GetConnectorsFromSealdId(sealdId string) ([]common_models.Connector, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = utils.CheckUUID(sealdId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return state.storage.connectors.getFromSealdId(sealdId), nil
}

// AddConnector adds a connector to the current identity. If no preValidationToken is given, the connector will need to be validated before use.
func (state *State) AddConnector(value string, connectorType common_models.ConnectorType, preValidationToken *utils.PreValidationToken) (*common_models.Connector, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if value == "" {
		return nil, tracerr.Wrap(ErrorAddConnectorEmptyValue)
	}
	var formattedValue string
	if connectorType == common_models.ConnectorTypeEmail {
		_, err := mail.ParseAddress(value)
		if err != nil {
			return nil, tracerr.Wrap(ErrorAddConnectorInvalidValueEmail.AddDetails(value))
		}
		formattedValue = strings.ToLower(value)
	} else if connectorType == common_models.ConnectorTypeApp {
		atIndex := strings.LastIndex(value, "@")
		if atIndex == -1 || utils.IsUUID(value[atIndex:]) {
			return nil, tracerr.Wrap(ErrorAddConnectorInvalidValueAP.AddDetails(value))
		}
		formattedValue = value
	} else {
		return nil, tracerr.Wrap(ErrorAddConnectorInvalidType)
	}

	connectorToAdd := &addConnectorRequest{Value: formattedValue, Type: connectorType}
	if preValidationToken != nil {
		connectorToAdd.PreValidationToken = preValidationToken
	}

	connectorAdded, err := autoLogin(state, state.apiClient.addConnector)(connectorToAdd)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	commonConnector := connectorAdded.ConnectorData.toCommonConnector()
	err = state.storage.connectors.set(commonConnector)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = state.saveConnectors()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &commonConnector, nil
}

// ValidateConnector validates an added connector that was added without a preValidationToken.
func (state *State) ValidateConnector(connectorId string, challenge string) (*common_models.Connector, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = utils.CheckUUID(connectorId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	if challenge == "" {
		return nil, tracerr.Wrap(ErrorValidateConnectorInvalidChallenge)
	}
	connectorToValidate := &validateConnectorRequest{ConnectorId: connectorId, Challenge: challenge}
	connectorValidated, err := autoLogin(state, state.apiClient.validateConnector)(connectorToValidate)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	commonValidatedConnector := connectorValidated.ConnectorData.toCommonConnector()
	err = state.storage.connectors.set(commonValidatedConnector)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &commonValidatedConnector, nil
}

// RemoveConnector removes a connector belonging to the current account.
func (state *State) RemoveConnector(connectorId string) (*common_models.Connector, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = utils.CheckUUID(connectorId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	connectorRemoved, err := autoLogin(state, state.apiClient.removeConnector)(&removeConnectorRequest{ConnectorId: connectorId})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	err = state.storage.connectors.remove(connectorRemoved.ConnectorData.toCommonConnector())
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	c := connectorRemoved.ConnectorData.toCommonConnector()
	return &c, nil
}

// ListConnectors lists connectors associated to the current account.
func (state *State) ListConnectors() ([]common_models.Connector, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	connectors, err := autoLogin(state, state.apiClient.listConnectors)(nil)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	var commonConnectors []common_models.Connector
	for _, c := range connectors.Connectors {
		comC := c.toCommonConnector()

		// If another identity took one of our old connector, we must keep the new one in local Storage
		// To simplify, we just ignore revoked and removed connectors
		if comC.State == common_models.ConnectorStateValidated || comC.State == common_models.ConnectorStatePending {
			commonConnectors = append(commonConnectors, comC)

			// We don't save pending connectors. They might overwrite an existing one
			if comC.State == common_models.ConnectorStateValidated {
				err = state.storage.connectors.set(comC)
				if err != nil {
					return nil, tracerr.Wrap(err)
				}
			}
		}
	}
	return commonConnectors, nil
}

// RetrieveConnector retrieves a connector by its connectorId, then updates the local cache of connectors.
func (state *State) RetrieveConnector(connectorId string) (*common_models.Connector, error) {
	state.locks.currentDeviceLock.RLock()
	defer state.locks.currentDeviceLock.RUnlock()
	err := state.checkSdkState(true)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	err = utils.CheckUUID(connectorId)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	connectorRetrieve, err := autoLogin(state, state.apiClient.retrieveConnector)(&retrieveConnectorRequest{ConnectorId: connectorId})
	if err != nil {
		return nil, tracerr.Wrap(err)
	}

	commonConnector := connectorRetrieve.ConnectorData.toCommonConnector()
	err = state.storage.connectors.set(commonConnector)
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	return &commonConnector, nil
}
