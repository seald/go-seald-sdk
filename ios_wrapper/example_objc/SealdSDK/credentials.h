//
//  credentials.h
//  SealdSDK demo app ios
//
//  Created by Mehdi on 21/02/2024.
//  Copyright © 2024 Seald SAS. All rights reserved.
//

#ifndef credentials_h
#define credentials_h

typedef struct {
    const NSString* apiURL;
    const NSString* appId;
    const NSString* JWTSharedSecretId;
    const NSString* JWTSharedSecret;
    const NSString* ssksURL;
    const NSString* ssksBackendAppKey;
    const NSString* ssksTMRChallenge;
} SealdCredentials;

extern SealdCredentials const sealdCredentials;

#endif /* credentials_h */
