//
// Created by clement on 25/04/23.
//

#ifndef GO_SEALD_SSKS_BACKEND_H
#define GO_SEALD_SSKS_BACKEND_H

#include "seald_sdk.h"

typedef struct {
    char* keyStorageURL;
    char* appId;
    char* appKey;
} SSKSBackend;

typedef struct {
    char* SessionId;
    int MustAuthenticate;
} ChallengeSendResponse;

SSKSBackend* New_SSKSBackend(char* keyStorageURL, char* appId, char* appKey);

int ssks_backend_challenge_send(SSKSBackend* session, char* userId, char* authFactorType, char* authFactorValue, int createUser, int forceAuth, ChallengeSendResponse** resp);

#endif //GO_SEALD_SSKS_BACKEND_H
