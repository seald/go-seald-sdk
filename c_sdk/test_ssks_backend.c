//go:build ignore

#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "test_ssks_backend.h"

SSKSBackend* New_SSKSBackend(char* keyStorageURL, char* appId, char* appKey) {
    SSKSBackend* backend = malloc(sizeof(SSKSBackend));
    backend->keyStorageURL = keyStorageURL;
    backend->appId = appId;
    backend->appKey = appKey;
    return backend;
}
struct MemoryStruct {
    char* memory;
    size_t size;
};

/*
 * This function is a callback function used by curl.h that performs HTTP requests and receives data.
 * When data is received, this function will append the newly received data to a dynamically growing memory buffer.
 */
static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;

    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int ssks_backend_post(SSKSBackend* session, char* endpointURL, char* json_data, char** resp) {
    CURL* curl_handle;
    CURLcode res;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1); // will be grown as needed by realloc above
    chunk.size = 0; // no data at this point

    curl_handle = curl_easy_init();
    if (curl_handle) {
        struct curl_slist* headers = NULL;
        char* appKeyHeader = malloc(strlen("X-SEALD-APIKEY: ") + strlen(session->appKey) + 1);
        sprintf(appKeyHeader, "%s%s", "X-SEALD-APIKEY: ", session->appKey);

        headers = curl_slist_append(headers, appKeyHeader);
        free(appKeyHeader);

        headers = curl_slist_append(headers, "Content-Type: application/json");

        char* appIdHeader = malloc(strlen("X-SEALD-APPID: ") + strlen(session->appId) + 1);

        sprintf(appIdHeader, "%s%s", "X-SEALD-APPID: ", session->appId);

        headers = curl_slist_append(headers, appIdHeader);
        free(appIdHeader);

        char* fullURL = malloc(strlen(session->keyStorageURL) + strlen(endpointURL) + 1);

        sprintf(fullURL, "%s%s", session->keyStorageURL, endpointURL);
        printf("SSKS Backend request to %s\n", fullURL);
        printf("Request body: %s\n", json_data);

        curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
        curl_easy_setopt(curl_handle, CURLOPT_URL, fullURL);
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&chunk);

        res = curl_easy_perform(curl_handle);
        if (res != CURLE_OK) {
            fprintf(stderr, "Failed to POST: %s\n", curl_easy_strerror(res));
            return 1;
        }
        // Get the response code
        long http_code = 0;
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

        *resp = strdup(chunk.memory);
        printf("SSKS Backend response %ld : %s\n", http_code, *resp);

        if (http_code != 200) {
            return 1;
        }

        curl_easy_cleanup(curl_handle);
        curl_slist_free_all(headers);
    } else {
        return 1;
    }

    return 0;
}

int ssks_backend_challenge_send(SSKSBackend* session, char* userId, char* authFactorType, char* authFactorValue, int createUser, int forceAuth, ChallengeSendResponse** resp) {
    char* output = malloc(109 + strlen(userId) + strlen(authFactorValue)); // buffer to store the formatted string
    sprintf(
        output,
        "{" \
        "\"user_id\": \"%s\", " \
        "\"auth_factor\": { " \
        "    \"type\": \"%s\", " \
        "    \"value\": \"%s\"" \
        "}," \
        "\"create_user\": %s," \
        "\"force_auth\": %s" \
        "}",
        userId, authFactorType, authFactorValue, createUser ? "true" : "false", forceAuth ? "true" : "false"
    );

    char* respString = NULL;
    char* endpoint = "tmr/back/challenge_send/";
    int err = ssks_backend_post(session, endpoint, output, &respString);
    if (err > 0) {
        return 1;
    }
    cJSON* root = cJSON_Parse(respString);
    if (!root) {
        printf("Error before: [%s]\n", cJSON_GetErrorPtr());
        return 1;
    }

    cJSON* sessionId = cJSON_GetObjectItemCaseSensitive(root, "session_id");
    cJSON* mustAuthenticate = cJSON_GetObjectItemCaseSensitive(root, "must_authenticate");

    ChallengeSendResponse* result = malloc(sizeof(ChallengeSendResponse));
    result->SessionId = strdup(cJSON_GetStringValue(sessionId));

    if (cJSON_IsTrue(mustAuthenticate)) {
        result->MustAuthenticate = 1;
    } else {
        result->MustAuthenticate = 0;
    }
    *resp = result;

    // Cleanup
    cJSON_Delete(root);
    free(respString);
    return 0;
}
