//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <jwt.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>

// Seald import
#include "seald_sdk.h" // The Seald SDK

// Tests helpers
#include "test_ssks_backend.h"

#define ASSERT_WITH_MSG(expr, msg) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "%s\n", msg); \
            assert(expr); \
        } \
    } while (0)

#define ASSERT_STRING_ENDSWITH(str1, str2) \
    do { \
        size_t len1 = strlen(str1); \
        size_t len2 = strlen(str2); \
        if (len1 < len2 || strcmp(str1 + len1 - len2, str2) != 0) { \
            fprintf(stderr, "Assertion failed in function %s in %s:%d : \"%s\" does not end with \"%s\"\n", __func__, __FILE__, __LINE__, str1, str2); \
            abort(); \
        } \
    } while (0)

#define ASSERT_STRING_EQUAL(str1, str2) \
    do { \
        if (strcmp(str1, str2) != 0) { \
            fprintf(stderr, "Assertion failed in function %s in %s:%d : \"%s\" does not equal \"%s\"\n", __func__, __FILE__, __LINE__, str1, str2); \
            abort(); \
        } \
    } while (0)

#define ASSERT_STRING_NOT_EQUAL(str1, str2) \
    do { \
        if (strcmp(str1, str2) == 0) { \
            fprintf(stderr, "Assertion failed in function %s in %s:%d : \"%s\" does equal \"%s\"\n", __func__, __FILE__, __LINE__, str1, str2); \
            abort(); \
        } \
    } while (0)

#define ASSERT_INT_EQUAL(int1, int2) \
    do { \
        if (int1 != int2) { \
            fprintf(stderr, "Assertion failed in function %s in %s:%d : \"%i\" does not equal \"%i\"\n", __func__, __FILE__, __LINE__, int1, int2); \
            abort(); \
        } \
    } while (0)

#define ASSERT_STRING_INCLUDE(str1, str2) \
    do { \
        if (strstr(str1, str2) == NULL) { \
            fprintf(stderr, "Assertion failed in function %s in %s:%d : \"%s\" does not include \"%s\"\n", __func__, __FILE__, __LINE__, str1, str2); \
            abort(); \
        } \
    } while (0)


char* generate_registration_jwt(char* JWTSharedSecret, char* JWTSharedSecretId, char* userId, char* appId, int joinTeam) {
    if (!joinTeam && !userId) {
        printf("Cannot create a JWT with neither joinTeam nor a userId\n");
        return NULL;
    }
    if (userId && !appId) {
        printf("Cannot create a JWT with a userId but no appId\n");
        return NULL;
    }

    jwt_t* jwt = NULL;
    jwt_new(&jwt);

    jwt_add_grant(jwt, "iss", JWTSharedSecretId);
    jwt_add_grant_int(jwt, "iat", time(NULL));

    if (joinTeam) {
        jwt_add_grant_bool(jwt, "join_team", 1);
    }

    if (userId) {
        char* prefix = "{\"connector_add\":{\"type\":\"AP\",\"value\":\"";
        char* suffix = "\"}}";
        char* value = malloc(strlen(prefix) + strlen(userId) + 1 + strlen(appId) + strlen(suffix) + 1);
        sprintf(value, "%s%s@%s%s", prefix, userId, appId, suffix);
        jwt_add_grants_json(jwt, value);
        free(value);
    }

    jwt_set_alg(jwt, JWT_ALG_HS256, (const unsigned char*)JWTSharedSecret, strlen(JWTSharedSecret));
    char* token = jwt_encode_str(jwt);

    jwt_free(jwt);

    return token;
}

typedef struct {
    char* apiURL;
    char* appId;
    char* JWTSharedSecretId;
    char* JWTSharedSecret;
    char* ssksUrl;
    char* ssksBackendAppKey;
    char* ssksTMRChallenge;
} TestCredentials;

void TestCredentials_Free(TestCredentials* tc) {
    if (tc != NULL) {
        free(tc->apiURL);
        free(tc->appId);
        free(tc->JWTSharedSecretId);
        free(tc->JWTSharedSecret);
        free(tc->ssksUrl);
        free(tc->ssksBackendAppKey);
        free(tc->ssksTMRChallenge);
        free(tc);
    }
}

TestCredentials* get_test_credentials() {
    // Open the JSON file
    FILE* fp = fopen("../test_credentials.json", "r");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }

    // Determine the size of the file
    fseek(fp, 0L, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    // Allocate a buffer for the JSON data
    char* buffer = malloc(file_size + 1);
    if (buffer == NULL) {
        perror("malloc");
        return NULL;
    }

    // Read the JSON data into the buffer
    size_t nread = fread(buffer, 1, file_size, fp);
    if (nread != file_size) {
        perror("fread");
        free(buffer);
        return NULL;
    }
    fclose(fp);
    buffer[file_size] = '\0';

    // Parse the JSON data into a cJSON object
    cJSON* root = cJSON_Parse(buffer);
    if (root == NULL) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return NULL;
    }

    TestCredentials* result = malloc(sizeof(TestCredentials));
    if (result == NULL) {
        perror("malloc");
        return NULL;
    }

    // Extract values from the cJSON object
    cJSON* apiUrlObj = cJSON_GetObjectItemCaseSensitive(root, "api_url");
    result->apiURL = strdup(cJSON_GetStringValue(apiUrlObj));

    cJSON* appIdObj = cJSON_GetObjectItemCaseSensitive(root, "app_id");
    result->appId = strdup(cJSON_GetStringValue(appIdObj));

    cJSON* jwtSharedSecretIdObj = cJSON_GetObjectItemCaseSensitive(root, "jwt_shared_secret_id");
    result->JWTSharedSecretId = strdup(cJSON_GetStringValue(jwtSharedSecretIdObj));

    cJSON* jwtSharedSecretObj = cJSON_GetObjectItemCaseSensitive(root, "jwt_shared_secret");
    result->JWTSharedSecret = strdup(cJSON_GetStringValue(jwtSharedSecretObj));

    cJSON* ssksUrl = cJSON_GetObjectItemCaseSensitive(root, "ssks_url");
    result->ssksUrl = strdup(cJSON_GetStringValue(ssksUrl));

    cJSON* ssksBackendAppKey = cJSON_GetObjectItemCaseSensitive(root, "ssks_backend_app_key");
    result->ssksBackendAppKey = strdup(cJSON_GetStringValue(ssksBackendAppKey));

    cJSON* ssksTMRChallenge = cJSON_GetObjectItemCaseSensitive(root, "ssks_tmr_challenge");
    result->ssksTMRChallenge = strdup(cJSON_GetStringValue(ssksTMRChallenge));

    // Cleanup
    cJSON_Delete(root);
    free(buffer);

    return result;
}

int remove_directory(const char* path) {
    DIR* dir = opendir(path);
    if (dir == NULL) {
        return -1;
    }

    struct dirent* entry;
    char filepath[1024];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

        if (entry->d_type == DT_DIR) {
            if (remove_directory(filepath) == -1) {
                return -1;
            }
        } else {
            if (remove(filepath) == -1) {
                return -1;
            }
        }
    }

    closedir(dir);
    if (remove(path) == -1) {
        return -1;
    }
    return 0;
}

int array_includes(char* array[], int arrayLen, char* value) {
    for (int i = 0; i < arrayLen; i++) {
        if (strcmp(array[i], value) == 0) {
            return 1;
        }
    }
    return 0;
}

char* randomString(int length) {
    static char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char* str = malloc(length + 1); // allocate memory for the string
    if (str) {
        srand(time(NULL)); // seed the random number generator with the current time
        for (int i = 0; i < length; i++) {
            int index = rand() % (sizeof(charset) - 1); // generate a random index within the range of the character set, excluding the termination symbol of the charset
            str[i] = charset[index]; // assign the character at the random index to the string
        }
        str[length] = '\0'; // terminate the string
    } else {
        exit(1);
    }
    return str;
}

unsigned char* randomBuffer(int length) {
    unsigned char* buffer = malloc(length); // allocate memory for the string
    if (buffer) {
        srand(time(NULL)); // seed the random number generator with the current time
        for (int i = 0; i < length; i++) {
            buffer[i] = rand() % 256; // generate a random value
        }
    }
    return buffer;
}

int testSealdSDK(TestCredentials* testCredentials) {
    int errCode = 0;
    SealdError* err = NULL;

    // The SealdSDK uses a local database. This database should be written to a permanent directory.
    char* sealdDir = "./test-dir/";

    // The Seald SDK uses a local database that will persist on disk.
    // When instantiating a SealdSDK, it is highly recommended to set a symmetric key to encrypt this database.
    // In an actual app, it should be generated at signup,
    // either on the server and retrieved from your backend at login,
    // or on the client-side directly and stored in the system's keychain.
    int databaseEncryptionKeyLen = 64;
    // WARNING: This should be a cryptographically random buffer of 64 bytes. This random generation is NOT good enough.
    unsigned char* databaseEncryptionKey = randomBuffer(databaseEncryptionKeyLen);

    // This demo expects a clean database path to create it's own data, so we need to clean what previous runs left.
    // In a real app, it should never be done.
    errCode = remove_directory(sealdDir);
    if (errCode != 0) {
        printf("Error on remove\n");
        // not returning, it may simply be the dir not existing
    }

    // Seald uses JWT to manage licenses and identity.
    // JWTs should be generated by your backend, and sent to the user at signup.
    // The JWT secretId and secret can be generated from your administration dashboard.
    // They should NEVER be on client side.
    // However, as this is a demo without a backend, we will use them on the frontend.
    // JWT documentation: https://docs.seald.io/en/sdk/guides/jwt.html
    // identity documentation: https://docs.seald.io/en/sdk/guides/4-identities.html

    // let's instantiate 3 SealdSDK. They will correspond to 3 users that will exchange messages.
    SealdInitializeOptions initOptions = {
        .ApiURL = testCredentials->apiURL,
        .AppId = testCredentials->appId,
        .KeySize = 1024, // in production, use 4096
        .DatabasePath = sealdDir,
        .DatabaseEncryptionKey = databaseEncryptionKey,
        .DatabaseEncryptionKeyLen = databaseEncryptionKeyLen,
        .EncryptionSessionCacheTTL = 0,
        .LogLevel = -1,
        .LogNoColor = 0,
        .InstanceName = "C-Instance-1",
        .Platform = "c-tests"
    };
    SealdSdk* sdk1;
    errCode = SealdSdk_Initialize(&initOptions, &sdk1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    initOptions.DatabasePath = ""; // In memory only
    initOptions.InstanceName = "C-Instance-2";
    SealdSdk* sdk2 = NULL;
    errCode = SealdSdk_Initialize(&initOptions, &sdk2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    initOptions.DatabasePath = NULL; // In memory only
    initOptions.InstanceName = "C-Instance-3";
    SealdSdk* sdk3 = NULL;
    errCode = SealdSdk_Initialize(&initOptions, &sdk3, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    // retrieve info about current user before creating a user should return null
    SealdAccountInfo* retrieveNoAccount = SealdSdk_GetCurrentAccountInfo(sdk1);
    assert(retrieveNoAccount == NULL);

    // Create the 3 accounts. Again, the signupJWT should be generated by your backend
    char* jwt1 = generate_registration_jwt(testCredentials->JWTSharedSecret, testCredentials->JWTSharedSecretId, NULL, NULL, 1);
    assert(jwt1 != NULL);
    SealdAccountInfo* createAccountResult1 = NULL;
    errCode = SealdSdk_CreateAccount(
        sdk1,
        "C-demo-user-1",
        "C-demo-device-1",
        jwt1,
        0,
        NULL,
        NULL,
        &createAccountResult1,
        &err
    );
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    free(jwt1);

    char* jwt2 = generate_registration_jwt(testCredentials->JWTSharedSecret, testCredentials->JWTSharedSecretId, NULL, NULL, 1);
    assert(jwt2 != NULL);
    SealdAccountInfo* createAccountResult2 = NULL;
    errCode = SealdSdk_CreateAccount(
        sdk2,
        "C-demo-user-2",
        "C-demo-device-2",
        jwt2,
        0,
        NULL,
        NULL,
        &createAccountResult2,
        &err
    );
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    free(jwt2);

    char* jwt3 = generate_registration_jwt(testCredentials->JWTSharedSecret, testCredentials->JWTSharedSecretId, NULL, NULL, 1);
    assert(jwt3 != NULL);
    SealdAccountInfo* createAccountResult3 = NULL;
    errCode = SealdSdk_CreateAccount(
        sdk3,
        "C-demo-user-3",
        "C-demo-device-3",
        jwt3,
        0,
        NULL,
        NULL,
        &createAccountResult3,
        &err
    );
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    free(jwt3);

    // retrieve info about current user after creating a user should return account info:
    SealdAccountInfo* retrieveAccountInfo = SealdSdk_GetCurrentAccountInfo(sdk1);
    ASSERT_STRING_EQUAL(retrieveAccountInfo->UserId, createAccountResult1->UserId);
    ASSERT_STRING_EQUAL(retrieveAccountInfo->DeviceId, createAccountResult1->DeviceId);
    assert(retrieveAccountInfo->DeviceExpires != 0);
    assert(retrieveAccountInfo->DeviceExpires == createAccountResult1->DeviceExpires);
    SealdAccountInfo_Free(retrieveAccountInfo);

    // Create group: https://docs.seald.io/sdk/guides/5-groups.html
    SealdStringArray* members = SealdStringArray_New();
    SealdStringArray_Add(members, createAccountResult1->UserId);
    SealdStringArray* admins = SealdStringArray_New();
    SealdStringArray_Add(admins, createAccountResult1->UserId);
    char* groupId = NULL;
    errCode = SealdSdk_CreateGroup(sdk1, "group-1", members, admins, NULL, NULL, &groupId, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdStringArray_Free(members);
    SealdStringArray_Free(admins);

    // Manage group members and admins
    // Add user2 as group member
    SealdStringArray* membersToAdd1 = SealdStringArray_New();
    SealdStringArray_Add(membersToAdd1, createAccountResult2->UserId);
    SealdStringArray* adminsToSet1 = SealdStringArray_New();
    errCode = SealdSdk_AddGroupMembers(sdk1, groupId, membersToAdd1, adminsToSet1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdStringArray_Free(membersToAdd1);
    SealdStringArray_Free(adminsToSet1);
    // user1 adds user3 as group member and group admin
    SealdStringArray* membersToAdd2 = SealdStringArray_New();
    SealdStringArray_Add(membersToAdd2, createAccountResult3->UserId);
    SealdStringArray* adminsToSet2 = SealdStringArray_New();
    SealdStringArray_Add(adminsToSet2, createAccountResult3->UserId);
    errCode = SealdSdk_AddGroupMembers(sdk1, groupId, membersToAdd2, adminsToSet2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdStringArray_Free(membersToAdd2);
    SealdStringArray_Free(adminsToSet2);
    // user3 can remove user2
    SealdStringArray* membersToRemove = SealdStringArray_New();
    SealdStringArray_Add(membersToRemove, createAccountResult2->UserId);
    errCode = SealdSdk_RemoveGroupMembers(sdk3, groupId, membersToRemove, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdStringArray_Free(membersToRemove);
    // user3 can remove user1 from admins
    SealdStringArray* addToAdmins = SealdStringArray_New();
    SealdStringArray* removeFromAdmins = SealdStringArray_New();
    SealdStringArray_Add(removeFromAdmins, createAccountResult1->UserId);
    errCode = SealdSdk_SetGroupAdmins(sdk3, groupId, addToAdmins, removeFromAdmins, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdStringArray_Free(addToAdmins);
    SealdStringArray_Free(removeFromAdmins);

    // Create encryption session: https://docs.seald.io/sdk/guides/6-encryption-sessions.html
    // user1, user2, and group as recipients
    // Default rights for the session creator (if included as recipients without RecipientRights)  read = true, forward = true, revoke = true
    // Default rights for any other recipient:  read = true, forward = true, revoke = false
    SealdRecipientsWithRightsArray* recipients = SealdRecipientsWithRightsArray_New();
    SealdRecipientsWithRightsArray_AddWithDefaultRights(recipients, createAccountResult1->UserId);
    SealdRecipientsWithRightsArray_AddWithDefaultRights(recipients, createAccountResult2->UserId);
    SealdRecipientsWithRightsArray_AddWithDefaultRights(recipients, groupId);
    SealdEncryptionSession* es1SDK1 = NULL;
    errCode = SealdSdk_CreateEncryptionSession(sdk1, recipients, 1, &es1SDK1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdRecipientsWithRightsArray_Free(recipients);
    SealdEncryptionSessionRetrievalDetails* es1SDK1RetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK1);
    ASSERT_INT_EQUAL(es1SDK1RetrievalDetails->Flow, SealdEncryptionSessionRetrievalCreated);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK1RetrievalDetails);

    // Retrieve session Id
    char* sessionId = SealdEncryptionSession_Id(es1SDK1);
    printf("Session ID: %s\n", sessionId);

    // Using two-man-rule accesses

    // Add TMR accesses to the session, then, retrieve the session using it.
    // Create TMR a recipient
    char* authFactorType = "EM";
    char* afRandString = randomString(10);
    char* authFactorValue = malloc(strlen("af_val-") + strlen(afRandString) + strlen("@test.com") + 1);
    sprintf(authFactorValue, "af_val-%s@test.com", afRandString);

    // WARNING: This should be a cryptographically random buffer of 64 bytes. This random generation is NOT good enough.
    int overEncryptionKeyLen = 64;
    unsigned char* overEncryptionKeyBytes = randomBuffer(overEncryptionKeyLen);

    // Add the TMR access
    char* addedTmrId = NULL;
    errCode = SealdEncryptionSession_AddTmrAccess(es1SDK1, authFactorType, authFactorValue, overEncryptionKeyBytes, overEncryptionKeyLen, 1, 1, 0, &addedTmrId, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(strlen(addedTmrId) == 36);
    free(afRandString);
    free(addedTmrId);

    // Retrieve the TMR JWT
    SealdSsksTMRPluginInitializeOptions tmrSsksInitOptions = {
        .SsksURL = testCredentials->ssksUrl,
        .AppId = testCredentials->appId,
        .LogLevel = -1,
        .LogNoColor = 0,
        .InstanceName = "tmr-access",
        .Platform = "c-tests"
    };
    SealdSsksTMRPlugin* ssksPluginTmrAccesses;
    errCode = SealdSsksTMRPlugin_Initialize(&tmrSsksInitOptions, &ssksPluginTmrAccesses, &err);
    SSKSBackend* yourCompanyDummyBackend = New_SSKSBackend(testCredentials->ssksUrl, testCredentials->appId, testCredentials->ssksBackendAppKey);

    // The app backend creates an SSKS authentication session.
    // This is the first time that this email is authenticating onto SSKS, so `mustAuthenticate` would be false, but we force auth because we want to convert TMR accesses.
    ChallengeSendResponse* authTmrSession = NULL;
    errCode = ssks_backend_challenge_send(yourCompanyDummyBackend, createAccountResult1->UserId, "EM", authFactorValue, 1, 1, &authTmrSession);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_INT_EQUAL(authTmrSession->MustAuthenticate, 1);

    // Retrieve a JWT associated with the authentication factor from SSKS
    SealdSsksTMRPluginGetFactorTokenResponse* retrievedToken = NULL;
    errCode = SealdSsksTMRPlugin_GetFactorToken(ssksPluginTmrAccesses, authTmrSession->SessionId, authFactorType, authFactorValue, testCredentials->ssksTMRChallenge, &retrievedToken, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdSsksTMRPlugin_Free(ssksPluginTmrAccesses);
    free(authTmrSession);

    // Retrieve the encryption session using the JWT
    SealdEncryptionSession* es1SDK1ByTmr = NULL;
    SealdTmrAccessesRetrievalFilters* tmrAccessesRetrievalFilters = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionByTmr(sdk2, retrievedToken->Token, sessionId, overEncryptionKeyBytes, overEncryptionKeyLen, tmrAccessesRetrievalFilters, 1, 1, &es1SDK1ByTmr, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdEncryptionSessionRetrievalDetails* es1SDK1ByTmrRetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK1ByTmr);
    ASSERT_INT_EQUAL(es1SDK1ByTmrRetrievalDetails->Flow, SealdEncryptionSessionRetrievalViaTmrAccess);
    SealdEncryptionSession_Free(es1SDK1ByTmr);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK1ByTmrRetrievalDetails);

    // Convert the TMR accesses
    SealdTmrAccessesConvertFilters* tmrAccessesConvertFilters = NULL;
    SealdConvertTmrAccessesResult* convertResult;
    errCode = SealdSdk_ConvertTmrAccesses(sdk2, retrievedToken->Token, overEncryptionKeyBytes, overEncryptionKeyLen, tmrAccessesConvertFilters, 1, &convertResult, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdConvertTmrAccessesResult_Free(convertResult);

    // After conversion, sdk2 can retrieve the encryption session directly.
    SealdEncryptionSession* es1SDK1Converted = NULL;
    errCode = SealdSdk_RetrieveEncryptionSession(sdk2, sessionId, 0, 0, 0, &es1SDK1Converted, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdEncryptionSessionRetrievalDetails* es1SDK1ConvertedRetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK1Converted);
    ASSERT_INT_EQUAL(es1SDK1ConvertedRetrievalDetails->Flow, SealdEncryptionSessionRetrievalDirect);
    SealdEncryptionSession_Free(es1SDK1Converted);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK1ConvertedRetrievalDetails);

    // Using proxy sessions: https://docs.seald.io/sdk/guides/proxy-sessions.html

    // Create proxy sessions:
    // user1 needs to be a recipient of this session in order to be able to add it as a proxy session
    SealdRecipientsWithRightsArray* proxyRecipients1 = SealdRecipientsWithRightsArray_New();
    SealdRecipientsWithRightsArray_AddWithDefaultRights(proxyRecipients1, createAccountResult1->UserId);
    SealdRecipientsWithRightsArray_AddWithDefaultRights(proxyRecipients1, createAccountResult3->UserId);
    SealdEncryptionSession* proxySession1 = NULL;
    errCode = SealdSdk_CreateEncryptionSession(sdk1, proxyRecipients1, 1, &proxySession1, &err);
    SealdRecipientsWithRightsArray_Free(proxyRecipients1);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* proxySession1Id = SealdEncryptionSession_Id(proxySession1);
    SealdEncryptionSession_Free(proxySession1);
    errCode = SealdEncryptionSession_AddProxySession(es1SDK1, proxySession1Id, 1, 1, 1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    // user1 needs to be a recipient of this session in order to be able to add it as a proxy session
    SealdRecipientsWithRightsArray* proxyRecipients2 = SealdRecipientsWithRightsArray_New();
    SealdRecipientsWithRightsArray_AddWithDefaultRights(proxyRecipients2, createAccountResult1->UserId);
    SealdRecipientsWithRightsArray_AddWithDefaultRights(proxyRecipients2, createAccountResult2->UserId);
    SealdEncryptionSession* proxySession2 = NULL;
    errCode = SealdSdk_CreateEncryptionSession(sdk1, proxyRecipients2, 1, &proxySession2, &err);
    SealdRecipientsWithRightsArray_Free(proxyRecipients2);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* proxySession2Id = SealdEncryptionSession_Id(proxySession2);
    SealdEncryptionSession_Free(proxySession2);
    errCode = SealdEncryptionSession_AddProxySession(es1SDK1, proxySession2Id, 1, 1, 1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    // The SealdEncryptionSession object can encrypt and decrypt for user1
    char* initialString = "a message that needs to be encrypted!";
    char* encryptedMessage = NULL;
    errCode = SealdEncryptionSession_EncryptMessage(es1SDK1, initialString, &encryptedMessage, &err);
    printf("encryptedMessage: %s\n", encryptedMessage);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* decryptedMessage = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(es1SDK1, encryptedMessage, &decryptedMessage, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(decryptedMessage, initialString);
    free(decryptedMessage);

    // user1 can parse/retrieve the EncryptionSession from the encrypted message
    SealdEncryptionSession* es1SDK1RetrieveFromMess = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk1, encryptedMessage, 0, 0, 0, &es1SDK1RetrieveFromMess, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* es1SDK1RetrieveFromMessId = SealdEncryptionSession_Id(es1SDK1RetrieveFromMess);
    ASSERT_STRING_EQUAL(es1SDK1RetrieveFromMessId, sessionId);
    free(es1SDK1RetrieveFromMessId);
    SealdEncryptionSessionRetrievalDetails* es1SDK1FromMessRetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK1RetrieveFromMess);
    ASSERT_INT_EQUAL(es1SDK1FromMessRetrievalDetails->Flow, SealdEncryptionSessionRetrievalDirect);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK1FromMessRetrievalDetails);
    char* decryptedMessageFromMess = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(
        es1SDK1RetrieveFromMess,
        encryptedMessage,
        &decryptedMessageFromMess,
        &err
    );
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(decryptedMessageFromMess, initialString);
    SealdEncryptionSession_Free(es1SDK1RetrieveFromMess);
    free(decryptedMessageFromMess);

    // Create a test file on disk that we will encrypt/decrypt
    char* fileContent = "File clear data.";
    char* filePath = "./test-dir/testfile.txt";
    FILE* fp = fopen(filePath, "w");
    assert(fp != NULL);
    errCode = fputs(fileContent, fp);
    assert(errCode >= 0);
    errCode = fclose(fp);
    assert(errCode == 0);

    // Encrypt the test file. Resulting file will be written alongside the source file, with `.seald` extension added
    char* encryptedFilePath = NULL;
    errCode = SealdEncryptionSession_EncryptFileFromPath(es1SDK1, filePath, &encryptedFilePath, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_ENDSWITH(encryptedFilePath, "/test-dir/testfile.txt.seald");

    // User1 can parse/retrieve the encryptionSession directly from the encrypted file
    SealdEncryptionSession* es1SDK1FromFile = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromFile(sdk1, encryptedFilePath, 0, 0, 0, &es1SDK1FromFile, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(SealdEncryptionSession_Id(es1SDK1FromFile), sessionId);
    SealdEncryptionSessionRetrievalDetails* es1SDK1FromFileRetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK1FromFile);
    ASSERT_INT_EQUAL(es1SDK1FromFileRetrievalDetails->Flow, SealdEncryptionSessionRetrievalDirect);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK1FromFileRetrievalDetails);

    // The retrieved session can decrypt the file.
    // The decrypted file will be named with the name it has at encryption. Any renaming of the encrypted file will be ignored.
    // NOTE: In this example, the decrypted file will have `(1)` suffix to avoid overwriting
    // the original clear file.
    char* decryptedFilePath = NULL;
    errCode = SealdEncryptionSession_DecryptFileFromPath(es1SDK1FromFile, encryptedFilePath, &decryptedFilePath, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_ENDSWITH(decryptedFilePath, "/test-dir/testfile (1).txt");
    char* decryptedFileContent = NULL;
    FILE* f = fopen(decryptedFilePath, "r");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    decryptedFileContent = malloc(fsize + 1);
    assert(decryptedFileContent != NULL);
    size_t bytesRead = fread(decryptedFileContent, 1, fsize, f);
    assert(bytesRead == fsize);
    decryptedFileContent[fsize] = '\0';
    fclose(f);
    ASSERT_STRING_EQUAL(decryptedFileContent, fileContent);
    SealdEncryptionSession_Free(es1SDK1FromFile);
    free(decryptedFilePath);
    free(decryptedFileContent);

    // User1 can parse/retrieve the EncryptionSession from the encrypted file bytes
    FILE* encryptedFile = fopen(encryptedFilePath, "rb");
    assert(encryptedFile != NULL);
    fseek(encryptedFile, 0, SEEK_END);
    long fileSize = ftell(encryptedFile);
    fseek(encryptedFile, 0, SEEK_SET);
    unsigned char* encryptedFileContent = (unsigned char*)malloc(fileSize);
    assert(encryptedFileContent != NULL);
    fread(encryptedFileContent, 1, fileSize, encryptedFile); // Read file content into memory
    fclose(encryptedFile); // Close the file
    free(encryptedFilePath);

    SealdEncryptionSession* es1SDK1RetrieveFromBytes = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromBytes(sdk1, encryptedFileContent, fileSize, 0, 0, 0, &es1SDK1RetrieveFromBytes, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    free(encryptedFileContent);

    char* es1SDK1RetrieveFromBytesId = SealdEncryptionSession_Id(es1SDK1RetrieveFromBytes);
    ASSERT_STRING_EQUAL(es1SDK1RetrieveFromBytesId, sessionId);
    free(es1SDK1RetrieveFromBytesId);
    SealdEncryptionSessionRetrievalDetails* es1SDK1FromBytesRetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK1RetrieveFromBytes);
    ASSERT_INT_EQUAL(es1SDK1FromBytesRetrievalDetails->Flow, SealdEncryptionSessionRetrievalDirect);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK1FromBytesRetrievalDetails);
    char* decryptedMessageFromBytes = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(
        es1SDK1RetrieveFromBytes,
        encryptedMessage,
        &decryptedMessageFromBytes,
        &err
    );
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(decryptedMessageFromBytes, initialString);
    SealdEncryptionSession_Free(es1SDK1RetrieveFromBytes);
    free(decryptedMessageFromBytes);

    // user2 can retrieve the SealdEncryptionSession from the session ID.
    SealdEncryptionSession* es1SDK2 = NULL;
    errCode = SealdSdk_RetrieveEncryptionSession(sdk2, sessionId, 0, 0, 0, &es1SDK2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* decryptedMessageSDK2 = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(es1SDK2, encryptedMessage, &decryptedMessageSDK2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(decryptedMessageSDK2, initialString);
    free(decryptedMessageSDK2);
    SealdEncryptionSessionRetrievalDetails* es1SDK2RetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK2);
    ASSERT_INT_EQUAL(es1SDK2RetrievalDetails->Flow, SealdEncryptionSessionRetrievalDirect);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK2RetrievalDetails);

    // user3 cannot retrieve the SealdEncryptionSession with lookupGroupKey set to false.
    SealdEncryptionSession* es1SDK3WithoutLookupGroup = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk3, encryptedMessage, 0, 0, 0, &es1SDK3WithoutLookupGroup, &err);
    assert(errCode == -1);
    ASSERT_STRING_EQUAL(err->Code, "NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Id, "GOSDK_NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Description, "Can't decipher this session");
    assert(es1SDK3WithoutLookupGroup == NULL);
    SealdError_Free(err);
    err = NULL;

    // user3 can retrieve the SealdEncryptionSession from the encrypted message through the group.
    SealdEncryptionSession* es1SDK3FromGroup = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk3, encryptedMessage, 0, 0, 1, &es1SDK3FromGroup, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdEncryptionSessionRetrievalDetails* es1SDK3FromGroupRetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK3FromGroup);
    ASSERT_INT_EQUAL(es1SDK3FromGroupRetrievalDetails->Flow, SealdEncryptionSessionRetrievalViaGroup);
    ASSERT_STRING_EQUAL(es1SDK3FromGroupRetrievalDetails->GroupId, groupId);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK3FromGroupRetrievalDetails);
    char* decryptedMessageSDK3 = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(es1SDK3FromGroup, encryptedMessage, &decryptedMessageSDK3, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(decryptedMessageSDK3, initialString);
    free(decryptedMessageSDK3);
    SealdEncryptionSession_Free(es1SDK3FromGroup);

    // user3 removes all members of "group-1". A group without member is deleted.
    SealdStringArray* membersToRemove2 = SealdStringArray_New();
    SealdStringArray_Add(membersToRemove2, createAccountResult1->UserId);
    SealdStringArray_Add(membersToRemove2, createAccountResult3->UserId);
    errCode = SealdSdk_RemoveGroupMembers(sdk3, groupId, membersToRemove2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdStringArray_Free(membersToRemove2);

    // user3 could retrieve the previous encryption session only because "group-1" was set as recipient.
    // As the group was deleted, it can no longer access it.
    // user3 still has the encryption session in its cache, but we can disable it.
    SealdEncryptionSession* es1SDK3AfterRemoveFromGroup = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk3, encryptedMessage, 0, 0, 1, &es1SDK3AfterRemoveFromGroup, &err);
    assert(errCode == -1);
    ASSERT_STRING_EQUAL(err->Code, "NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Id, "GOSDK_NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Description, "Can't decipher this session");
    assert(es1SDK3AfterRemoveFromGroup == NULL);
    SealdError_Free(err);
    err = NULL;

    // user3 can still retrieve the session via proxy
    SealdEncryptionSession* es1SDK3FromProxy = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk3, encryptedMessage, 0, 1, 0, &es1SDK3FromProxy, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdEncryptionSessionRetrievalDetails* es1SDK3FromProxyRetrievalDetails = SealdEncryptionSession_RetrievalDetails(es1SDK3FromProxy);
    ASSERT_INT_EQUAL(es1SDK3FromProxyRetrievalDetails->Flow, SealdEncryptionSessionRetrievalViaProxy);
    ASSERT_STRING_EQUAL(es1SDK3FromProxyRetrievalDetails->ProxySessionId, proxySession1Id);
    SealdEncryptionSessionRetrievalDetails_Free(es1SDK3FromProxyRetrievalDetails);
    SealdEncryptionSession_Free(es1SDK3FromProxy);

    // user2 adds user3 as recipient of the encryption session.
    SealdActionStatusArray* asListAdd = NULL;
    SealdRecipientsWithRightsArray* recipientsToAdd = SealdRecipientsWithRightsArray_New();
    SealdRecipientsWithRightsArray_AddWithDefaultRights(recipientsToAdd, createAccountResult3->UserId);

    errCode = SealdEncryptionSession_AddRecipients(es1SDK2, recipientsToAdd, &asListAdd, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdActionStatusArray_Size(asListAdd) == 1);
    SealdActionStatus* asFromList = SealdActionStatusArray_Get(asListAdd, 0);
    ASSERT_STRING_EQUAL(asFromList->Id, createAccountResult3->DeviceId); // Note that addRecipient return DeviceId, not UserId
    assert(asFromList->Success == 1);
    SealdRecipientsWithRightsArray_Free(recipientsToAdd);
    SealdActionStatusArray_Free(asListAdd);

    // user3 can now retrieve it without group or proxy.
    SealdEncryptionSession* es1SDK3 = NULL;
    errCode = SealdSdk_RetrieveEncryptionSession(sdk3, sessionId, 0, 0, 0, &es1SDK3, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* decryptedMessageAfterAdd = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(es1SDK3, encryptedMessage, &decryptedMessageAfterAdd, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(decryptedMessageAfterAdd, initialString);
    free(decryptedMessageAfterAdd);
    SealdEncryptionSession_Free(es1SDK3);

    // user1 revokes user3 and proxy1 from the encryption session.
    SealdStringArray* recipientsToRevoke = SealdStringArray_New();
    SealdStringArray_Add(recipientsToRevoke, createAccountResult3->UserId);
    SealdStringArray* proxiesToRevoke = SealdStringArray_New();
    SealdStringArray_Add(proxiesToRevoke, proxySession1Id);
    SealdRevokeResult* resultRevoke = NULL;
    errCode = SealdEncryptionSession_RevokeRecipients(es1SDK1, recipientsToRevoke, proxiesToRevoke, &resultRevoke, &err);
    SealdStringArray_Free(recipientsToRevoke);
    SealdStringArray_Free(proxiesToRevoke);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdActionStatusArray_Size(resultRevoke->Recipients) == 1);
    SealdActionStatus* asFromListRevoke = SealdActionStatusArray_Get(resultRevoke->Recipients, 0); // no need to free
    ASSERT_STRING_EQUAL(asFromListRevoke->Id, createAccountResult3->UserId);
    assert(asFromListRevoke->Success == 1);
    assert(SealdActionStatusArray_Size(resultRevoke->ProxySessions) == 1);
    SealdActionStatus* asFromListRevokeProxy = SealdActionStatusArray_Get(resultRevoke->ProxySessions, 0); // no need to free
    ASSERT_STRING_EQUAL(asFromListRevokeProxy->Id, proxySession1Id);
    assert(asFromListRevokeProxy->Success == 1);
    SealdRevokeResult_Free(resultRevoke);

    // user3 cannot retrieve the session anymore, even with proxy or group
    SealdEncryptionSession* es1SDK3AfterRevoke = NULL;
    errCode = SealdSdk_RetrieveEncryptionSession(sdk3, sessionId, 0, 1, 1, &es1SDK3AfterRevoke, &err);
    assert(errCode == -1);
    ASSERT_STRING_EQUAL(err->Code, "NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Id, "GOSDK_NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Description, "Can't decipher this session");
    assert(es1SDK3AfterRevoke == NULL);
    SealdError_Free(err);
    err = NULL;

    // user1 revokes all other recipients from the session
    SealdRevokeResult* resultRevokeOther = NULL;
    errCode = SealdEncryptionSession_RevokeOthers(es1SDK1, &resultRevokeOther, &err); // revoke user2 + group (user3 is already revoked) + proxy2
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdActionStatusArray_Size(resultRevokeOther->Recipients) == 2);
    char* expectedRevokeOtherIds[] = {groupId, createAccountResult2->UserId};
    SealdActionStatus* revokeOther0 = SealdActionStatusArray_Get(resultRevokeOther->Recipients, 0);
    assert(revokeOther0->Success == 1);
    assert(array_includes(expectedRevokeOtherIds, 3, revokeOther0->Id) == 1);
    SealdActionStatus* revokeOther1 = SealdActionStatusArray_Get(resultRevokeOther->Recipients, 1);
    assert(revokeOther1->Success == 1);
    assert(array_includes(expectedRevokeOtherIds, 3, revokeOther1->Id) == 1);
    assert(SealdActionStatusArray_Size(resultRevokeOther->ProxySessions) == 1);
    SealdActionStatus* asFromListRevokeOtherProxy = SealdActionStatusArray_Get(resultRevokeOther->ProxySessions, 0); // no need to free
    ASSERT_STRING_EQUAL(asFromListRevokeOtherProxy->Id, proxySession2Id);
    assert(asFromListRevokeOtherProxy->Success == 1);
    SealdRevokeResult_Free(resultRevokeOther);

    // user2 cannot retrieve the session anymore
    SealdEncryptionSession* es1SDK2AfterRevoke = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk2, encryptedMessage, 0, 0, 0, &es1SDK2AfterRevoke, &err);
    assert(errCode == -1);
    ASSERT_STRING_EQUAL(err->Code, "NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Id, "GOSDK_NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Description, "Can't decipher this session");
    assert(es1SDK2AfterRevoke == NULL);
    SealdError_Free(err);
    err = NULL;

    // user1 revokes all. It can no longer retrieve it.
    SealdRevokeResult* resultRevokeAll = NULL;
    errCode = SealdEncryptionSession_RevokeAll(es1SDK1, &resultRevokeAll, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdActionStatusArray_Size(resultRevokeAll->Recipients) == 1); // only user1 is left
    SealdActionStatus* asRevokeAll0 = SealdActionStatusArray_Get(resultRevokeAll->Recipients, 0);
    ASSERT_STRING_EQUAL(asRevokeAll0->Id, createAccountResult1->UserId);
    assert(SealdActionStatusArray_Size(resultRevokeAll->ProxySessions) == 0);
    SealdRevokeResult_Free(resultRevokeAll);

    // user1 cannot retrieve anymore
    SealdEncryptionSession* es1SDK1AfterRevoke = NULL;
    errCode = SealdSdk_RetrieveEncryptionSession(sdk1, sessionId, 0, 0, 0, &es1SDK1AfterRevoke, &err);
    assert(errCode != 0);
    ASSERT_STRING_EQUAL(err->Code, "NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Id, "GOSDK_NO_TOKEN_FOR_YOU");
    ASSERT_STRING_EQUAL(err->Description, "Can't decipher this session");
    assert(es1SDK1AfterRevoke == NULL);
    SealdError_Free(err);
    err = NULL;
    free(proxySession1Id);
    free(proxySession2Id);
    free(sessionId);
    free(encryptedMessage);
    SealdEncryptionSession_Free(es1SDK2);
    SealdEncryptionSession_Free(es1SDK1);

    // Create additional data for user1
    SealdRecipientsWithRightsArray* recipients234 = SealdRecipientsWithRightsArray_New();
    SealdRecipientsWithRightsArray_AddWithDefaultRights(recipients234, createAccountResult1->UserId);
    SealdEncryptionSession* es2SDK1 = NULL;
    errCode = SealdSdk_CreateEncryptionSession(sdk1, recipients234, 1, &es2SDK1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* anotherMessage = "Nobody should read that!";
    char* secondEncryptedMessage = NULL;
    errCode = SealdEncryptionSession_EncryptMessage(es2SDK1, anotherMessage, &secondEncryptedMessage, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdEncryptionSession* es3SDK1 = NULL;
    errCode = SealdSdk_CreateEncryptionSession(sdk1, recipients234, 1, &es3SDK1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdEncryptionSession* es4SDK1 = NULL;
    errCode = SealdSdk_CreateEncryptionSession(sdk1, recipients234, 1, &es4SDK1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdRecipientsWithRightsArray_Free(recipients234);

    // user1 can retrieveMultiple
    SealdStringArray* sessionIds = SealdStringArray_New();
    char* es2SDK1Id = SealdEncryptionSession_Id(es2SDK1);
    char* es3SDK1Id = SealdEncryptionSession_Id(es3SDK1);
    char* es4SDK1Id = SealdEncryptionSession_Id(es4SDK1);
    SealdStringArray_Add(sessionIds, es2SDK1Id);
    SealdStringArray_Add(sessionIds, es3SDK1Id);
    SealdStringArray_Add(sessionIds, es4SDK1Id);
    SealdEncryptionSessionArray* encryptionSessions = NULL;
    errCode = SealdSdk_RetrieveMultipleEncryptionSessions(sdk1, sessionIds, 0, 0, 0, &encryptionSessions, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(encryptionSessions != NULL);
    ASSERT_INT_EQUAL(SealdEncryptionSessionArray_Size(encryptionSessions), 3);
    SealdEncryptionSession* encryptionSessions0 = SealdEncryptionSessionArray_Get(encryptionSessions, 0);
    char* encryptionSessions0Id = SealdEncryptionSession_Id(encryptionSessions0);
    ASSERT_STRING_EQUAL(encryptionSessions0Id, es2SDK1Id);
    SealdEncryptionSession* encryptionSessions1 = SealdEncryptionSessionArray_Get(encryptionSessions, 1);
    char* encryptionSessions1Id = SealdEncryptionSession_Id(encryptionSessions1);
    ASSERT_STRING_EQUAL(encryptionSessions1Id, es3SDK1Id);
    SealdEncryptionSession* encryptionSessions2 = SealdEncryptionSessionArray_Get(encryptionSessions, 2);
    char* encryptionSessions2Id = SealdEncryptionSession_Id(encryptionSessions2);
    ASSERT_STRING_EQUAL(encryptionSessions2Id, es4SDK1Id);
    free(es2SDK1Id);
    free(es3SDK1Id);
    free(es4SDK1Id);
    SealdEncryptionSession_Free(encryptionSessions0);
    free(encryptionSessions0Id);
    SealdEncryptionSession_Free(encryptionSessions1);
    free(encryptionSessions1Id);
    SealdEncryptionSession_Free(encryptionSessions2);
    free(encryptionSessions2Id);
    SealdStringArray_Free(sessionIds);
    SealdEncryptionSessionArray_Free(encryptionSessions);

    // user1 can renew its key, and still decrypt old messages
    unsigned char* preparedRenewal = NULL;
    int preparedRenewalLen = 0;
    errCode = SealdSdk_PrepareRenew(sdk1, NULL, NULL, &preparedRenewal, &preparedRenewalLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    // `preparedRenewal` Can be stored on SSKS as a new identity. That way, a backup will be available is the renewKeys fail.

    errCode = SealdSdk_RenewKeys(sdk1, 5 * 365 * 24 * 60 * 60, NULL, NULL, preparedRenewal, preparedRenewalLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdEncryptionSession* es2SDK1AfterRenew = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(
        sdk1,
        secondEncryptedMessage,
        0,
        0,
        0,
        &es2SDK1AfterRenew,
        &err
    );
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* decryptedMessageAfterRenew = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(
        es2SDK1AfterRenew,
        secondEncryptedMessage,
        &decryptedMessageAfterRenew,
        &err
    );
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(decryptedMessageAfterRenew, anotherMessage);
    SealdEncryptionSession_Free(es2SDK1AfterRenew);
    free(decryptedMessageAfterRenew);
    SealdEncryptionSession_Free(es2SDK1);
    SealdEncryptionSession_Free(es3SDK1);
    SealdEncryptionSession_Free(es4SDK1);
    free(groupId);

    // CONNECTORS https://docs.seald.io/en/sdk/guides/jwt.html#adding-a-userid

    // we can add a custom userId using a JWT
    char* customConnectorJWTValue = "user1-custom-id";
    char* addConnectorJWT = generate_registration_jwt(
        testCredentials->JWTSharedSecret,
        testCredentials->JWTSharedSecretId,
        customConnectorJWTValue,
        testCredentials->appId,
        0
    );
    errCode = SealdSdk_PushJWT(sdk1, addConnectorJWT, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    free(addConnectorJWT);

    // we can list a user connectors
    SealdConnectorsArray* connectorsList = NULL;
    errCode = SealdSdk_ListConnectors(sdk1, &connectorsList, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdConnectorsArray_Size(connectorsList) == 1);
    SealdConnector* connectorFromList = SealdConnectorsArray_Get(connectorsList, 0);
    ASSERT_STRING_EQUAL(connectorFromList->State, "VO");
    ASSERT_STRING_EQUAL(connectorFromList->Type, "AP");
    ASSERT_STRING_EQUAL(connectorFromList->SealdId, createAccountResult1->UserId);
    char* connectorValue = malloc(strlen(customConnectorJWTValue) + strlen(testCredentials->appId) + 2);
    sprintf(connectorValue, "%s@%s", customConnectorJWTValue, testCredentials->appId);
    ASSERT_STRING_EQUAL(connectorFromList->Value, connectorValue);

    // Retrieve connector by its id
    SealdConnector* retrieveConnector = NULL;
    errCode = SealdSdk_RetrieveConnector(sdk1, connectorFromList->Id, &retrieveConnector, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(retrieveConnector->State, "VO");
    ASSERT_STRING_EQUAL(retrieveConnector->Type, "AP");
    ASSERT_STRING_EQUAL(retrieveConnector->SealdId, createAccountResult1->UserId);
    ASSERT_STRING_EQUAL(retrieveConnector->Value, connectorValue);
    SealdConnector_Free(retrieveConnector);

    // Retrieve connectors from a user id.
    SealdConnectorsArray* connectorsFromSealdId = NULL;
    errCode = SealdSdk_GetConnectorsFromSealdId(sdk1, createAccountResult1->UserId, &connectorsFromSealdId, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdConnectorsArray_Size(connectorsFromSealdId) == 1);
    SealdConnector* connectorFromSealdId = SealdConnectorsArray_Get(connectorsFromSealdId, 0);
    ASSERT_STRING_EQUAL(connectorFromSealdId->State, "VO");
    ASSERT_STRING_EQUAL(connectorFromSealdId->Type, "AP");
    ASSERT_STRING_EQUAL(connectorFromSealdId->SealdId, createAccountResult1->UserId);
    ASSERT_STRING_EQUAL(connectorFromSealdId->Value, connectorValue);
    SealdConnectorsArray_Free(connectorsFromSealdId);

    // Get sealdId of a user from a connector
    SealdConnectorTypeValueArray* connectorTypeValues = SealdConnectorTypeValueArray_New();
    SealdConnectorTypeValueArray_Add(connectorTypeValues, "AP", connectorValue);
    SealdStringArray* sealdIds = NULL;
    errCode = SealdSdk_GetSealdIdsFromConnectors(sdk1, connectorTypeValues, &sealdIds, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdStringArray_Size(sealdIds) == 1);
    char* sealdId = SealdStringArray_Get(sealdIds, 0);
    ASSERT_STRING_EQUAL(sealdId, createAccountResult1->UserId);
    free(sealdId);
    SealdConnectorTypeValueArray_Free(connectorTypeValues);
    SealdStringArray_Free(sealdIds);

    // user1 can remove a connector
    SealdConnector* removeConnector = NULL;
    errCode = SealdSdk_RemoveConnector(sdk1, connectorFromList->Id, &removeConnector, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(removeConnector->State, "RE");
    ASSERT_STRING_EQUAL(removeConnector->Type, "AP");
    ASSERT_STRING_EQUAL(removeConnector->SealdId, createAccountResult1->UserId);
    ASSERT_STRING_EQUAL(removeConnector->Value, connectorValue);
    SealdConnector_Free(removeConnector);
    free(connectorValue);
    SealdConnectorsArray_Free(connectorsList);

    // verify that no connector left
    SealdConnectorsArray* connectorListAfterRevoke = NULL;
    errCode = SealdSdk_ListConnectors(sdk1, &connectorListAfterRevoke, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdConnectorsArray_Size(connectorListAfterRevoke) == 0);
    SealdConnectorsArray_Free(connectorListAfterRevoke);

    // user1 can export its identity
    unsigned char* exportIdentity = NULL;
    int exportIdentityLen = 0;
    errCode = SealdSdk_ExportIdentity(sdk1, &exportIdentity, &exportIdentityLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    // We can instantiate a new SealdSDK, import the exported identity
    initOptions.DatabasePath = "./test-dir/sdk1Exported";
    initOptions.InstanceName = "sdk1Exported";
    SealdSdk* sdk1Exported = NULL;
    errCode = SealdSdk_Initialize(&initOptions, &sdk1Exported, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    errCode = SealdSdk_ImportIdentity(sdk1Exported, exportIdentity, exportIdentityLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    free(exportIdentity);

    // SDK with imported identity can decrypt
    SealdEncryptionSession* es2SDK1Exported = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk1Exported, secondEncryptedMessage, 0, 0, 0, &es2SDK1Exported, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* clearMessageExportedIdentity = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(es2SDK1Exported, secondEncryptedMessage, &clearMessageExportedIdentity, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(clearMessageExportedIdentity, anotherMessage);
    SealdEncryptionSession_Free(es2SDK1Exported);
    free(clearMessageExportedIdentity);
    errCode = SealdSdk_Close(sdk1Exported, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    // user1 can create sub identity
    SealdCreateSubIdentityResponse* subIdentity = NULL;
    errCode = SealdSdk_CreateSubIdentity(sdk1, "SUB-deviceName", 5 * 365 * 24 * 60 * 60, NULL, NULL, &subIdentity, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(strlen(subIdentity->DeviceId) == 36);

    // can list devices missing keys
    sleep(3); // sleeping for 3s, to let pre-provisioning do its thing
    SealdDeviceMissingKeysArray* deviceMissingKeysArray = NULL;
    errCode = SealdSdk_DevicesMissingKeys(sdk1, 0, &deviceMissingKeysArray, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdDeviceMissingKeysArray_Size(deviceMissingKeysArray) == 1);
    SealdDeviceMissingKeys* deviceMissingKeys = SealdDeviceMissingKeysArray_Get(deviceMissingKeysArray, 0);
    ASSERT_STRING_EQUAL(deviceMissingKeys->DeviceId, subIdentity->DeviceId);
    SealdDeviceMissingKeysArray_Free(deviceMissingKeysArray);

    // first device needs to reencrypt for the new device
    SealdMassReencryptResponse massReencryptResponse;
    errCode = SealdSdk_MassReencrypt(sdk1, subIdentity->DeviceId, SealdMassReencryptOptions_Defaults(), &massReencryptResponse, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(massReencryptResponse.Reencrypted > 0);
    assert(massReencryptResponse.Failed == 0);

    // after reencryption, no more devices missing keys
    SealdDeviceMissingKeysArray* deviceMissingKeysArrayAfter = NULL;
    errCode = SealdSdk_DevicesMissingKeys(sdk1, 0, &deviceMissingKeysArrayAfter, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(SealdDeviceMissingKeysArray_Size(deviceMissingKeysArrayAfter) == 0);
    SealdDeviceMissingKeysArray_Free(deviceMissingKeysArrayAfter);

    // We can instantiate a new SealdSDK, import the sub-device identity
    initOptions.DatabasePath = "./test-dir/sdk1Subdevice";
    initOptions.InstanceName = "C-Instance-1-subdevice";
    SealdSdk* sdk1SubDevice = NULL;
    errCode = SealdSdk_Initialize(&initOptions, &sdk1SubDevice, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    errCode = SealdSdk_ImportIdentity(sdk1SubDevice, subIdentity->BackupKey, subIdentity->BackupKeyLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdCreateSubIdentityResponse_Free(subIdentity);

    // sub device can decrypt
    SealdEncryptionSession* es2SDK1SubDevice = NULL;
    errCode = SealdSdk_RetrieveEncryptionSessionFromMessage(sdk1SubDevice, secondEncryptedMessage, 0, 0, 0, &es2SDK1SubDevice, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    char* clearMessageSubdIdentity = NULL;
    errCode = SealdEncryptionSession_DecryptMessage(es2SDK1SubDevice, secondEncryptedMessage, &clearMessageSubdIdentity, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(clearMessageSubdIdentity, anotherMessage);
    SealdEncryptionSession_Free(es2SDK1SubDevice);
    free(clearMessageSubdIdentity);
    free(secondEncryptedMessage);

    errCode = SealdSdk_Close(sdk1SubDevice, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    // Get and Check sigchain hash
    SealdGetSigchainResponse* sdk1LastSigchainHash = NULL;
    errCode = SealdSdk_GetSigchainHash(sdk1, createAccountResult1->UserId, -1, &sdk1LastSigchainHash, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_WITH_MSG(sdk1LastSigchainHash->Position == 2, "Got hash at invalid position");

    SealdGetSigchainResponse* sdk1FirstSigchainHash = NULL;
    errCode = SealdSdk_GetSigchainHash(sdk1, createAccountResult1->UserId, 0, &sdk1FirstSigchainHash, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_WITH_MSG(sdk1FirstSigchainHash->Position == 0, "Got hash at invalid position");

    SealdCheckSigchainResponse* checkLastSigchainHash = NULL;
    errCode = SealdSdk_CheckSigchainHash(sdk2, createAccountResult1->UserId, sdk1LastSigchainHash->Hash, -1, &checkLastSigchainHash, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_WITH_MSG(checkLastSigchainHash->Found == 1, "Sigchain hash not found");
    ASSERT_WITH_MSG(checkLastSigchainHash->Position == 2, "Sigchain invalid hash position");
    ASSERT_WITH_MSG(checkLastSigchainHash->LastPosition == 2, "Invalid sigchain length");

    SealdCheckSigchainResponse* checkFirstSigchainHash = NULL;
    errCode = SealdSdk_CheckSigchainHash(sdk1, createAccountResult1->UserId, sdk1FirstSigchainHash->Hash, -1, &checkFirstSigchainHash, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_WITH_MSG(checkFirstSigchainHash->Found == 1, "Sigchain hash not found");
    ASSERT_WITH_MSG(checkFirstSigchainHash->Position == 0, "Sigchain invalid hash position");
    ASSERT_WITH_MSG(checkFirstSigchainHash->LastPosition == 2, "Invalid sigchain length");

    SealdCheckSigchainResponse* badPositionCheck = NULL;
    errCode = SealdSdk_CheckSigchainHash(sdk2, createAccountResult1->UserId, sdk1FirstSigchainHash->Hash, 1, &badPositionCheck, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_WITH_MSG(badPositionCheck->Found == 0, "Sigchain hash unexpectedly found");
    // For badPositionCheck, position cannot be asserted as it is not set when the hash is not found.
    ASSERT_WITH_MSG(badPositionCheck->LastPosition == 2, "Invalid sigchain length");
    SealdGetSigchainResponse_Free(sdk1LastSigchainHash);
    SealdGetSigchainResponse_Free(sdk1FirstSigchainHash);
    free(checkLastSigchainHash);
    free(checkFirstSigchainHash);
    free(badPositionCheck);

    // Group TMR temporary keys

    // First, create a group to test on. sdk1 create a TMR temporary key to this group, sdk2 will join.
    SealdStringArray* membersGTMR = SealdStringArray_New();
    SealdStringArray_Add(membersGTMR, createAccountResult1->UserId);
    SealdStringArray* adminsGTMR = SealdStringArray_New();
    SealdStringArray_Add(adminsGTMR, createAccountResult1->UserId);
    char* groupTMRId = NULL;
    errCode = SealdSdk_CreateGroup(sdk1, "group-tmr", membersGTMR, adminsGTMR, NULL, NULL, &groupTMRId, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    SealdStringArray_Free(membersGTMR);
    SealdStringArray_Free(adminsGTMR);

    // WARNING: This should be a cryptographically random buffer of 64 bytes. This random generation is NOT good enough.
    int gTMRRawOverEncryptionKeyLen = 64;
    unsigned char* gTMRRawOverEncryptionKeyBytes = randomBuffer(gTMRRawOverEncryptionKeyLen);

    // We defined a two man rule recipient earlier. We will use it again.
    // The authentication factor is defined by `authFactorType` and `authFactorValue`.
    // Also we already have the TMR JWT associated with it: `retrievedToken->Token`

    SealdGroupTMRTemporaryKey* gTMRCreated = NULL;
    errCode = SealdSdk_CreateGroupTMRTemporaryKey(sdk1, groupTMRId, authFactorType, authFactorValue, 0, gTMRRawOverEncryptionKeyBytes, gTMRRawOverEncryptionKeyLen, &gTMRCreated, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    SealdGroupTMRTemporaryKeysArray* gTMRList = NULL;
    int gTMRListNbPage = 0;
    errCode = SealdSdk_ListGroupTMRTemporaryKeys(sdk1, groupTMRId, 1, 1, &gTMRListNbPage, &gTMRList, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_WITH_MSG(gTMRListNbPage == 1, "Unexpected number of pages");
    assert(SealdGroupTMRTemporaryKeysArray_Size(gTMRList) == 1);
    SealdGroupTMRTemporaryKey* gTMRListed = SealdGroupTMRTemporaryKeysArray_Get(gTMRList, 0);
    ASSERT_STRING_EQUAL(gTMRListed->Id, gTMRCreated->Id);
    SealdGroupTMRTemporaryKeysArray_Free(gTMRList);

    SealdGroupTMRTemporaryKeysArray* gTMRSearch = NULL;
    int gTMRSearchNbPage = 0;
    SealdSearchGroupTMRTemporaryKeysOpts searchTMROpts = {
        .GroupId = groupTMRId,
    };
    errCode = SealdSdk_SearchGroupTMRTemporaryKeys(sdk1, retrievedToken->Token, &searchTMROpts, &gTMRSearchNbPage, &gTMRSearch, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_WITH_MSG(gTMRSearchNbPage == 1, "Unexpected number of pages");
    SealdGroupTMRTemporaryKeysArray_Free(gTMRSearch);

    errCode = SealdSdk_ConvertGroupTMRTemporaryKey(sdk2, groupTMRId, gTMRCreated->Id, retrievedToken->Token, gTMRRawOverEncryptionKeyBytes, gTMRRawOverEncryptionKeyLen, 0, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    errCode = SealdSdk_DeleteGroupTMRTemporaryKey(sdk1, groupTMRId, gTMRCreated->Id, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    SealdSsksTMRPluginGetFactorTokenResponse_Free(retrievedToken);
    SealdGroupTMRTemporaryKey_Free(gTMRCreated);
    free(authFactorValue);

    // Heartbeat can be used to check if proxies and firewalls are configured properly so that the app can reach Seald's servers.
    errCode = SealdSdk_Heartbeat(sdk1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    // close SDKs
    SealdAccountInfo_Free(createAccountResult1);
    SealdAccountInfo_Free(createAccountResult2);
    SealdAccountInfo_Free(createAccountResult3);
    errCode = SealdSdk_Close(sdk1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    errCode = SealdSdk_Close(sdk2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    errCode = SealdSdk_Close(sdk3, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);

    printf("SDK tests success!\n");
    return 0;
}

int testSealdSsksPassword(TestCredentials* testCredentials) {
    int errCode = 0;
    SealdError* err = NULL;

    char* randUID = randomString(10);
    char* userId = malloc(strlen("user-") + 10 + 1);
    sprintf(userId, "user-%s", randUID);

    // Simulating a Seald identity with random data, for a simpler example.
    int dummyIdentityLen = 10;
    unsigned char* dummyIdentity = randomBuffer(dummyIdentityLen); // should be the result of: SealdSdk_ExportIdentity()

    SealdSsksPasswordPluginInitializeOptions initOptions = {
        .SsksURL = testCredentials->ssksUrl,
        .AppId = testCredentials->appId,
        .LogLevel = -1,
        .LogNoColor = 0,
        .InstanceName = "myCInstance-1",
        .Platform = "c-tests"
    };
    SealdSsksPasswordPlugin* ssksPlugin;
    errCode = SealdSsksPasswordPlugin_Initialize(&initOptions, &ssksPlugin, &err);
    assert(errCode == 0);

    // Test with password
    char* userPassword = randomString(10);

    // Saving the identity with a password
    char* ssksId1 = NULL;
    errCode = SealdSsksPasswordPlugin_SaveIdentityFromPassword(ssksPlugin, userId, userPassword, dummyIdentity, dummyIdentityLen, &ssksId1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(ssksId1 != NULL);

    // Retrieving the identity with the password
    unsigned char* retrievedIdentity = NULL;
    int retrievedIdentityLen = 0;
    errCode = SealdSsksPasswordPlugin_RetrieveIdentityFromPassword(ssksPlugin, userId, userPassword, &retrievedIdentity, &retrievedIdentityLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(retrievedIdentityLen == dummyIdentityLen);
    assert(memcmp(dummyIdentity, retrievedIdentity, dummyIdentityLen) == 0);

    // Changing the password
    char* newPassword = "newPassword";
    char* ssksId1b = NULL;
    errCode = SealdSsksPasswordPlugin_ChangeIdentityPassword(ssksPlugin, userId, userPassword, newPassword, &ssksId1b, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_NOT_EQUAL(ssksId1b, ssksId1);

    // The previous password does not work anymore
    free(retrievedIdentity);
    retrievedIdentityLen = 0;
    errCode = SealdSsksPasswordPlugin_RetrieveIdentityFromPassword(ssksPlugin, userId, userPassword, &retrievedIdentity, &retrievedIdentityLen, &err);
    assert(errCode != 0);
    ASSERT_STRING_EQUAL(err->Code, "SSKSPASSWORD_CANNOT_FIND_IDENTITY");
    SealdError_Free(err);
    err = NULL;

    // Retrieving with the new password works
    errCode = SealdSsksPasswordPlugin_RetrieveIdentityFromPassword(ssksPlugin, userId, newPassword, &retrievedIdentity, &retrievedIdentityLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(retrievedIdentityLen == dummyIdentityLen);
    assert(memcmp(dummyIdentity, retrievedIdentity, dummyIdentityLen) == 0);

    // Test with raw keys
    char* rawStorageKey = randomString(32);
    int rawEncryptionKeyLen = 64;
    unsigned char* rawEncryptionKey = randomBuffer(rawEncryptionKeyLen);

    char* randUID2 = randomString(10);
    char* userIdRawKeys = malloc(strlen("user-") + 10 + 1);
    sprintf(userId, "user-%s", randUID2);

    // Saving identity with raw keys
    char* ssksId2 = NULL;
    errCode = SealdSsksPasswordPlugin_SaveIdentityFromRawKeys(ssksPlugin, userId, rawStorageKey, rawEncryptionKey, rawEncryptionKeyLen, dummyIdentity, dummyIdentityLen, &ssksId2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(ssksId2 != NULL);

    // Retrieving the identity with raw keys
    free(retrievedIdentity);
    retrievedIdentityLen = 0;
    errCode = SealdSsksPasswordPlugin_RetrieveIdentityFromRawKeys(ssksPlugin, userId, rawStorageKey, rawEncryptionKey, rawEncryptionKeyLen, &retrievedIdentity, &retrievedIdentityLen, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(retrievedIdentityLen == dummyIdentityLen);
    assert(memcmp(dummyIdentity, retrievedIdentity, dummyIdentityLen) == 0);

    // Deleting the identity by saving an empty buffer
    unsigned char* emptyIdentity = NULL;
    char* ssksId2b = NULL;
    errCode = SealdSsksPasswordPlugin_SaveIdentityFromRawKeys(ssksPlugin, userId, rawStorageKey, rawEncryptionKey, rawEncryptionKeyLen, emptyIdentity, 0, &ssksId2b, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(ssksId2b, ssksId2);

    // After deleting the identity, cannot retrieve anymore
    errCode = SealdSsksPasswordPlugin_RetrieveIdentityFromRawKeys(ssksPlugin, userId, rawStorageKey, rawEncryptionKey, rawEncryptionKeyLen, &retrievedIdentity, &retrievedIdentityLen, &err);
    assert(errCode != 0);
    ASSERT_STRING_EQUAL(err->Code, "SSKSPASSWORD_CANNOT_FIND_IDENTITY");
    SealdError_Free(err);
    err = NULL;

    // Cleanup
    free(rawStorageKey);
    free(rawEncryptionKey);
    free(randUID);
    free(randUID2);
    free(userId);
    free(dummyIdentity);
    free(userPassword);
    free(userIdRawKeys);
    free(retrievedIdentity);
    SealdSsksPasswordPlugin_Free(ssksPlugin);

    printf("SSKS Password tests success!\n");

    return 0;
}

int testSealdSsksTMR(TestCredentials* testCredentials) {
    int errCode = 0;
    SealdError* err = NULL;

    // rawTMRSymKey is a secret, generated and stored by your _backend_, unique for the user.
    // It can be retrieved by client-side when authenticated (usually as part of signup/sign-in call response).
    // This *MUST* be a cryptographically random buffer of 64 bytes.
    int rawTMRSymKeyLen = 64;
    unsigned char* rawTMRSymKey = randomBuffer(rawTMRSymKeyLen);

    // First, we need to simulate a user. For a simpler example, we will use random data.
    // userId is the ID of the user in your app.
    char* randString = randomString(10);
    char* userId = malloc(strlen("user-") + strlen(randString) + 1);
    sprintf(userId, "user-%s", randString);
    int dummyIdentityLen = 10;
    // userIdentity is the user's exported identity that you want to store on SSKS
    unsigned char* dummyIdentity = randomBuffer(dummyIdentityLen); // should be the result of: SealdSdk_ExportIdentity()

    // Define an authentication factor: the user's email address.
    // An authentication factor type can be an email `EM` or a phone number `SMS`
    char* userEM = malloc(strlen("email-") + strlen(randString) + strlen("@test.com") + 1);
    sprintf(userEM, "email-%s@test.com", randString);

    SSKSBackend* yourCompanyDummyBackend = New_SSKSBackend(testCredentials->ssksUrl, testCredentials->appId, testCredentials->ssksBackendAppKey);

    SealdSsksTMRPluginInitializeOptions initOptions = {
        .SsksURL = testCredentials->ssksUrl,
        .AppId = testCredentials->appId,
        .LogLevel = -1,
        .LogNoColor = 0,
        .InstanceName = "myCInstance-1",
        .Platform = "c-tests"
    };
    SealdSsksTMRPlugin* ssksPlugin;
    errCode = SealdSsksTMRPlugin_Initialize(&initOptions, &ssksPlugin, &err);
    assert(errCode == 0);

    // The app backend creates an SSKS authentication session to save the identity.
    // This is the first time that this email is storing an identity, so `must_authenticate` is false.
    ChallengeSendResponse* authSessionSave = NULL;
    errCode = ssks_backend_challenge_send(yourCompanyDummyBackend, userId, "EM", userEM, 1, 0, &authSessionSave);
    assert(errCode == 0);
    assert(authSessionSave->MustAuthenticate == 0);

    // Saving the identity. No challenge necessary because `must_authenticate` is false.
    SealdSsksTMRPluginSaveIdentityResponse* saveIdentityRes1 = NULL;
    errCode = SealdSsksTMRPlugin_SaveIdentity(ssksPlugin, authSessionSave->SessionId, "EM", userEM, rawTMRSymKey, rawTMRSymKeyLen, dummyIdentity, dummyIdentityLen, NULL, &saveIdentityRes1, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_NOT_EQUAL(saveIdentityRes1->SsksId, "");
    assert(saveIdentityRes1->AuthenticatedSessionId == NULL);

    // The app backend creates another session to retrieve the identity.
    // The identity is already saved, so `must_authenticate` is true.
    ChallengeSendResponse* authSessionRetrieve = NULL;
    errCode = ssks_backend_challenge_send(yourCompanyDummyBackend, userId, "EM", userEM, 1, 0, &authSessionRetrieve);
    assert(errCode == 0);
    assert(authSessionRetrieve->MustAuthenticate == 1);

    // Retrieving identity. Challenge is necessary for this.
    SealdSsksTMRPluginRetrieveIdentityResponse* retrieveResp = NULL;
    errCode = SealdSsksTMRPlugin_RetrieveIdentity(ssksPlugin, authSessionRetrieve->SessionId, "EM", userEM, rawTMRSymKey, rawTMRSymKeyLen, testCredentials->ssksTMRChallenge, &retrieveResp, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(retrieveResp->ShouldRenewKey == 1);
    assert(memcmp(dummyIdentity, retrieveResp->Identity, dummyIdentityLen) == 0);

    // If initial key has been saved without being fully authenticated, you should renew the user's private key, and save it again.
    // errCode = SealdSdk_RenewKeys(sdk1, 5 * 365 * 24 * 60 * 60, NULL, NULL, preparedRenewal, preparedRenewalLen, &err);
    // ASSERT_WITH_MSG(errCode == 0, err->Id);

    // Let's simulate the renew with another random identity
    unsigned char* dummyIdentity2 = randomBuffer(dummyIdentityLen); // should be the result of: SealdSdk_ExportIdentity()
    // to save the newly renewed identity on the server, you can use the `authenticatedSessionId` from the response to `SealdSsksTMRPlugin_RetrieveIdentity`, with no challenge
    SealdSsksTMRPluginSaveIdentityResponse* saveIdentityRes2 = NULL;
    errCode = SealdSsksTMRPlugin_SaveIdentity(ssksPlugin, retrieveResp->AuthenticatedSessionId, "EM", userEM, rawTMRSymKey, rawTMRSymKeyLen, dummyIdentity2, dummyIdentityLen, NULL, &saveIdentityRes2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    ASSERT_STRING_EQUAL(saveIdentityRes2->SsksId, saveIdentityRes1->SsksId);
    assert(saveIdentityRes2->AuthenticatedSessionId == NULL);

    // And now let's retrieve this new saved identity
    ChallengeSendResponse* authSessionRetrieve2 = NULL;
    errCode = ssks_backend_challenge_send(yourCompanyDummyBackend, userId, "EM", userEM, 1, 0, &authSessionRetrieve2);
    assert(errCode == 0);
    assert(authSessionRetrieve2->MustAuthenticate == 1);
    SealdSsksTMRPluginRetrieveIdentityResponse* retrieveResp2 = NULL;
    errCode = SealdSsksTMRPlugin_RetrieveIdentity(ssksPlugin, authSessionRetrieve2->SessionId, "EM", userEM, rawTMRSymKey, rawTMRSymKeyLen, testCredentials->ssksTMRChallenge, &retrieveResp2, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(retrieveResp2->ShouldRenewKey == 0);
    assert(memcmp(dummyIdentity2, retrieveResp2->Identity, dummyIdentityLen) == 0);

    // Try retrieving with another SealdSsksTMRPlugin instance
    SealdSsksTMRPluginInitializeOptions initOptions2 = {
        .SsksURL = testCredentials->ssksUrl,
        .AppId = testCredentials->appId,
        .LogLevel = -1,
        .LogNoColor = 0,
        .InstanceName = "myCInstance-2",
        .Platform = "c-tests"
    };
    SealdSsksTMRPlugin* ssksPlugin2;
    errCode = SealdSsksTMRPlugin_Initialize(&initOptions2, &ssksPlugin2, &err);
    ChallengeSendResponse* authSessionRetrieve3 = NULL;
    errCode = ssks_backend_challenge_send(yourCompanyDummyBackend, userId, "EM", userEM, 1, 0, &authSessionRetrieve3);
    assert(errCode == 0);
    assert(authSessionRetrieve3->MustAuthenticate == 1);
    SealdSsksTMRPluginRetrieveIdentityResponse* retrieveResp3 = NULL;
    errCode = SealdSsksTMRPlugin_RetrieveIdentity(ssksPlugin2, authSessionRetrieve3->SessionId, "EM", userEM, rawTMRSymKey, rawTMRSymKeyLen, testCredentials->ssksTMRChallenge, &retrieveResp3, &err);
    ASSERT_WITH_MSG(errCode == 0, err->Id);
    assert(retrieveResp3->ShouldRenewKey == 0);
    assert(memcmp(dummyIdentity2, retrieveResp3->Identity, dummyIdentityLen) == 0);

    // Cleanup
    free(randString);
    free(rawTMRSymKey);
    free(dummyIdentity);
    free(dummyIdentity2);
    free(userId);
    free(userEM);
    free(authSessionSave);
    free(authSessionRetrieve);
    free(authSessionRetrieve2);
    free(authSessionRetrieve3);
    SealdSsksTMRPluginRetrieveIdentityResponse_Free(retrieveResp);
    SealdSsksTMRPluginRetrieveIdentityResponse_Free(retrieveResp2);
    SealdSsksTMRPluginRetrieveIdentityResponse_Free(retrieveResp3);
    SealdSsksTMRPlugin_Free(ssksPlugin);
    SealdSsksTMRPlugin_Free(ssksPlugin2);

    printf("SSKS TMR tests success!\n");

    return 0;
}

int main() {
    curl_global_init(CURL_GLOBAL_ALL);
    int errCode = 0;

    TestCredentials* testCredentials = get_test_credentials();
    printf("Read test credentials:\n- apiURL: %s\n- appId: %s\n- JWTSharedSecretId: %s\n- JWTSharedSecret: %s\n", testCredentials->apiURL, testCredentials->appId, testCredentials->JWTSharedSecretId, testCredentials->JWTSharedSecret);

    errCode = testSealdSDK(testCredentials);
    assert(errCode == 0);

    errCode = testSealdSsksPassword(testCredentials);
    assert(errCode == 0);

    errCode = testSealdSsksTMR(testCredentials);
    assert(errCode == 0);

    // Cleanup
    TestCredentials_Free(testCredentials);
    curl_global_cleanup();
    return 0;
}
