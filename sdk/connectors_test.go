package sdk

import (
	"fmt"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/test_utils"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ztrue/tracerr"
	"testing"
)

func TestState_GetSealdIdFromConnector(t *testing.T) {
	credentials, err := test_utils.GetCredentials()
	if err != nil {
		t.Log("error should be nil")
		tracerr.Print(err)
		t.Fail()
		return
	}

	accountWithConnectors, err := createTestAccount("sdk_connectors_with_connectors")
	require.NoError(t, err)
	currentDeviceWithConnectors := accountWithConnectors.storage.currentDevice.get()

	nonce, err := utils.GenerateRandomNonce()
	require.NoError(t, err)

	var accountConnectors []*ConnectorTypeValue
	n := 0
	for n < 3 {
		userCustomId := fmt.Sprintf("AP-C-%d-%s@%s", n, nonce[:10], credentials.AppId)
		claims := test_utils.Claims{
			Scopes:       []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam, test_utils.PermissionAddConnector},
			ConnectorAdd: test_utils.ConnectorAdd{Type: common_models.ConnectorTypeApp, Value: userCustomId},
		}

		connectorJWT, err := test_utils.GetJWT(claims)
		require.NoError(t, err)
		err = accountWithConnectors.PushJWT(connectorJWT)
		require.NoError(t, err)

		accountConnectors = append(accountConnectors, &ConnectorTypeValue{Type: common_models.ConnectorTypeApp, Value: userCustomId})
		n++
	}

	t.Parallel()
	t.Run("Add, Validate, List, Remove", func(t *testing.T) {
		t.Parallel()
		t.Run("basic test", func(t *testing.T) {
			account, err := createTestAccount("sdk_connectors_basic")
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()

			APValue := fmt.Sprintf("AP-%s@%s", nonce[10:20], credentials.AppId)
			EMValue := fmt.Sprintf("em-%s@cou.cou", nonce[10:20])

			connectorEM, err := account.AddConnector(EMValue, common_models.ConnectorTypeEmail, nil)
			require.NoError(t, err)
			assert.Equal(t, EMValue, connectorEM.Value)
			assert.Equal(t, currentDevice.UserId, connectorEM.SealdId)
			assert.Equal(t, common_models.ConnectorTypeEmail, connectorEM.Type)
			assert.Equal(t, common_models.ConnectorStatePending, connectorEM.State)

			preValidationToken, err := utils.GeneratePreValidationToken(APValue, credentials.DomainValidationKey, credentials.DomainValidationKeyId)
			require.NoError(t, err)
			connectorAP, err := account.AddConnector(APValue, common_models.ConnectorTypeApp, preValidationToken)
			require.NoError(t, err)
			assert.Equal(t, APValue, connectorAP.Value)
			assert.Equal(t, currentDevice.UserId, connectorAP.SealdId)
			assert.Equal(t, common_models.ConnectorTypeApp, connectorAP.Type)
			assert.Equal(t, common_models.ConnectorStateValidated, connectorAP.State)

			list, err := account.ListConnectors()
			require.NoError(t, err)
			assert.Equal(t, 2, len(list))
			assert.True(t, utils.SliceSameMembers(list, []common_models.Connector{*connectorEM, *connectorAP}))

			connectorEMValidated, err := account.ValidateConnector(connectorEM.Id, "000-000")
			require.NoError(t, err)
			assert.Equal(t, EMValue, connectorEMValidated.Value)
			assert.Equal(t, currentDevice.UserId, connectorEMValidated.SealdId)
			assert.Equal(t, common_models.ConnectorTypeEmail, connectorEMValidated.Type)
			assert.Equal(t, common_models.ConnectorStateValidated, connectorEMValidated.State)

			retrieveConnector, err := account.RetrieveConnector(connectorEM.Id)
			require.NoError(t, err)
			connectorEM.State = common_models.ConnectorStateValidated
			assert.Equal(t, connectorEM, retrieveConnector)

			removedConnector, err := account.RemoveConnector(connectorEM.Id)
			require.NoError(t, err)
			connectorEM.State = common_models.ConnectorStateRevoked
			assert.Equal(t, connectorEM, removedConnector)

			listAtEnd, err := account.ListConnectors()
			require.NoError(t, err)
			assert.Equal(t, 1, len(listAtEnd))
			assert.Equal(t, []common_models.Connector{*connectorAP}, listAtEnd)
		})
		t.Run("Remove API fail ListConnect", func(t *testing.T) {
			account, err := createTestAccount("sdk_connectors_remove")
			require.NoError(t, err)

			canaryApi := newCanaryBeardApiClient(account.apiClient)
			account.apiClient = canaryApi

			EMValue := fmt.Sprintf("em-%s@cou.cou", nonce[12:22])
			connectorEM, err := account.AddConnector(EMValue, common_models.ConnectorTypeEmail, nil)

			canaryApi.ToExecute["addConnector"] = test_utils.SyntheticErrorCallback
			_, err = account.AddConnector(EMValue, common_models.ConnectorTypeEmail, nil)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)

			_, err = account.ValidateConnector(connectorEM.Id, "000-000")
			require.NoError(t, err)
			_, err = account.ValidateConnector(connectorEM.Id, "000-000")
			assert.ErrorIs(t, err, utils.APIError{Status: 400, Code: "CONNECTOR_ALREADY_VALIDATED"})

			canaryApi.ToExecute["removeConnector"] = test_utils.SyntheticErrorCallback
			_, err = account.RemoveConnector(connectorEM.Id)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)

			canaryApi.ToExecute["retrieveConnector"] = test_utils.SyntheticErrorCallback
			_, err = account.RetrieveConnector(connectorEM.Id)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)

			canaryApi.ToExecute["listConnectors"] = test_utils.SyntheticErrorCallback
			_, err = account.ListConnectors()
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)
		})

		t.Run("Misc input validation", func(t *testing.T) {
			account, err := createTestAccount("sdk_connectors_input_validation")
			require.NoError(t, err)
			currentDevice := account.storage.currentDevice.get()

			_, err = account.AddConnector("", common_models.ConnectorTypeEmail, nil)
			assert.ErrorIs(t, err, ErrorAddConnectorEmptyValue)
			_, err = account.AddConnector("dummyVamue", "NOP", nil)
			assert.ErrorIs(t, err, ErrorAddConnectorInvalidType)
			_, err = account.AddConnector("dummyValue", common_models.ConnectorTypeEmail, nil)
			assert.ErrorIs(t, err, ErrorAddConnectorInvalidValueEmail)
			_, err = account.AddConnector("dummyValue", common_models.ConnectorTypeApp, nil)
			assert.ErrorIs(t, err, ErrorAddConnectorInvalidValueAP)

			_, err = account.ValidateConnector("", "")
			assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
			_, err = account.ValidateConnector(currentDevice.UserId, "") // We need a valid UUID to reach the challenge validator
			assert.ErrorIs(t, err, ErrorValidateConnectorInvalidChallenge)

			_, err = account.RetrieveConnector("")
			assert.ErrorIs(t, err, utils.ErrorInvalidUUID)

			_, err = account.RemoveConnector("")
			assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
		})
	})

	t.Run("GetConnectorsFromSealdId", func(t *testing.T) {
		searchAccount, err := createTestAccount("sdk_connectors_get_connectors")
		require.NoError(t, err)
		// Check DB before
		assert.Equal(t, 0, len(searchAccount.storage.connectors.all()))

		// Searching should populate local DB
		_, err = searchAccount.GetSealdIdsFromConnectors(accountConnectors)
		require.NoError(t, err)

		found, err := searchAccount.GetConnectorsFromSealdId(currentDeviceWithConnectors.UserId)
		assert.Equal(t, 3, len(found))
		for _, c := range found {
			assert.Equal(t, currentDeviceWithConnectors.UserId, c.SealdId)
		}

		_, err = searchAccount.GetConnectorsFromSealdId("NotAnUUID")
		assert.ErrorIs(t, err, utils.ErrorInvalidUUID)
	})

	t.Run("GetSealdIdFromConnector", func(t *testing.T) {
		t.Parallel()
		t.Run("can do Basic search, connectors are saved in DB", func(t *testing.T) {
			searchAccount, err := createTestAccount("sdk_connectors_get_sealdids")
			require.NoError(t, err)

			// Check DB before
			assert.Equal(t, 0, len(searchAccount.storage.connectors.all()))

			found, err := searchAccount.GetSealdIdsFromConnectors(accountConnectors[:1])
			require.NoError(t, err)

			// Check result
			assert.Equal(t, 1, len(found))
			assert.Equal(t, currentDeviceWithConnectors.UserId, found[0])

			// Check DB after
			assert.Equal(t, 1, len(searchAccount.storage.connectors.all()))
			knownConnector, err := searchAccount.storage.connectors.getByValue(accountConnectors[0].Value, accountConnectors[0].Type)
			require.NoError(t, err)
			assert.Equal(t, currentDeviceWithConnectors.UserId, knownConnector.SealdId)
		})

		t.Run("dedupe input", func(t *testing.T) {
			searchAccount, err := createTestAccount("sdk_connectors_dedupe")
			require.NoError(t, err)

			sameConnectors := []*ConnectorTypeValue{accountConnectors[0], accountConnectors[0], accountConnectors[0]}
			found, err := searchAccount.GetSealdIdsFromConnectors(sameConnectors)
			require.NoError(t, err)

			assert.Equal(t, 1, len(found))
			assert.Equal(t, currentDeviceWithConnectors.UserId, found[0])
		})

		t.Run("search multiple connectors", func(t *testing.T) {
			found, err := accountWithConnectors.GetSealdIdsFromConnectors(accountConnectors)
			require.NoError(t, err)
			assert.Equal(t, 3, len(found))
			assert.Equal(t, currentDeviceWithConnectors.UserId, found[0])
			assert.Equal(t, currentDeviceWithConnectors.UserId, found[1])
			assert.Equal(t, currentDeviceWithConnectors.UserId, found[2])
		})

		t.Run("nil connectors", func(t *testing.T) {
			_, err := accountWithConnectors.GetSealdIdsFromConnectors(nil)
			assert.ErrorIs(t, err, ErrorGetSealdIdsFromConnectorsNoConnectors)
		})

		t.Run("api error", func(t *testing.T) {
			canaryAccount, err := createTestAccount("sdk_connectors_api_error")
			require.NoError(t, err)

			canaryApi := newCanaryBeardApiClient(canaryAccount.apiClient)
			canaryAccount.apiClient = canaryApi

			canaryApi.ToExecute["verifyConnector"] = func(_ any) ([]byte, error) {
				return nil, tracerr.Wrap(test_utils.ErrorSyntheticTestError)
			}

			_, err = canaryAccount.GetSealdIdsFromConnectors(accountConnectors)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)
		})

		t.Run("write DB error", func(t *testing.T) {
			canaryAccount, err := createTestAccount("sdk_connectors_db_error")
			require.NoError(t, err)

			canaryStorage := newCanaryFileStorage(canaryAccount.options.Database)
			canaryAccount.options.Database = canaryStorage

			canaryStorage.ToExecute["WriteConnectors"] = func() error {
				return tracerr.Wrap(test_utils.ErrorSyntheticTestError)
			}

			_, err = canaryAccount.GetSealdIdsFromConnectors(accountConnectors)
			assert.ErrorIs(t, err, test_utils.ErrorSyntheticTestError)
		})
	})

	t.Run("Test local Storage and compatibilty with jwt added connectors", func(t *testing.T) {
		account, err := createTestAccount("sdk_connectors_jwt")
		require.NoError(t, err)
		currentDevice := account.storage.currentDevice.get()

		// No connector to begin with
		assert.Equal(t, 0, len(account.storage.connectors.all()))
		sealdIdConnectors, err := account.GetConnectorsFromSealdId(currentDevice.UserId)
		require.NoError(t, err)
		assert.Equal(t, 0, len(sealdIdConnectors))
		accountConnectors, err := account.ListConnectors()
		require.NoError(t, err)
		assert.Equal(t, 0, len(accountConnectors))

		userCustomId := fmt.Sprintf("myid-%s@%s", nonce[30:40], credentials.AppId)
		claims := test_utils.Claims{
			Scopes:       []test_utils.JWTPermissionScopes{test_utils.PermissionJoinTeam, test_utils.PermissionAddConnector},
			ConnectorAdd: test_utils.ConnectorAdd{Type: common_models.ConnectorTypeApp, Value: userCustomId},
		}

		jwt, err := test_utils.GetJWT(claims)
		if err != nil {
			tracerr.Print(err)
			t.Fail()
			return
		}

		err = account.PushJWT(jwt)
		require.NoError(t, err)
		expectedConnectorTypeValue := ConnectorTypeValue{Value: userCustomId, Type: common_models.ConnectorTypeApp}

		assert.Equal(t, 1, len(account.storage.connectors.all()))
		knownConnector, err := account.storage.connectors.getByValue(userCustomId, common_models.ConnectorTypeApp)
		assert.Equal(t, currentDevice.UserId, knownConnector.SealdId)
		assert.Equal(t, common_models.ConnectorStateValidated, knownConnector.State)
		assert.Equal(t, common_models.ConnectorTypeApp, knownConnector.Type)
		assert.Equal(t, userCustomId, knownConnector.Value)
		expectedConnectorId := knownConnector.Id
		assert.NotEmpty(t, expectedConnectorId)

		foundSealdIds, err := account.GetSealdIdsFromConnectors([]*ConnectorTypeValue{&expectedConnectorTypeValue})
		require.NoError(t, err)
		assert.Equal(t, []string{currentDevice.UserId}, foundSealdIds)

		sealdIdConnectors, err = account.GetConnectorsFromSealdId(currentDevice.UserId)
		require.NoError(t, err)
		assert.Equal(t, []common_models.Connector{{
			Id:      expectedConnectorId,
			SealdId: currentDevice.UserId,
			State:   common_models.ConnectorStateValidated,
			Type:    common_models.ConnectorTypeApp,
			Value:   userCustomId,
		}}, sealdIdConnectors)

		accountConnectors, err = account.ListConnectors()
		require.NoError(t, err)
		assert.Equal(t, []common_models.Connector{{
			Id:      expectedConnectorId,
			SealdId: currentDevice.UserId,
			State:   common_models.ConnectorStateValidated,
			Type:    common_models.ConnectorTypeApp,
			Value:   userCustomId,
		}}, accountConnectors)
	})
}
