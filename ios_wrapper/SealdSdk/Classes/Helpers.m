//
//  Helpers.m
//  SealdSdk
//
//  Created by Mehdi Kouhen on 22/02/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

#import "SealdSdk.h"
#import "Helpers.h"

NSString*const SealdErrorDomain = @"SealdErrorDomain";

void _SealdInternal_ConvertError(NSError* originalError, NSError*_Nullable* errorPtr) {
    if (originalError == nil) { // no error, nothing to do
        return;
    }
    if (errorPtr == nil) { // no pointer, nowhere to store, error ignored
        return;
    }

    NSData* jsonData = [originalError.localizedDescription dataUsingEncoding:NSUTF8StringEncoding];
    NSError* jsonError = nil;
    NSDictionary* jsonDict = [NSJSONSerialization JSONObjectWithData:jsonData options:kNilOptions error:&jsonError];

    // Initialize default values
    NSNumber* status = nil;
    NSString* code = @"FAILED_DESERIALIZATION";
    NSString* idValue = @"FAILED_DESERIALIZATION";
    NSString* description = nil;
    NSString* details = nil;
    NSString* raw = nil;
    NSString* nativeStack = nil;

    // Update values
    // If there was an error parsing the JSON
    if (jsonError) {
        // Handle or log the JSON parsing error
        NSLog(@"JSON parsing error: %@", jsonError.localizedDescription);
        raw = originalError.localizedDescription;
    } else if (jsonDict) {
        status = jsonDict[@"status"];
        code = jsonDict[@"code"] ?: code;
        idValue = jsonDict[@"id"] ?: idValue;
        description = jsonDict[@"description"];
        details = jsonDict[@"details"];
        raw = jsonDict[@"raw"] ?: raw;
        nativeStack = jsonDict[@"stack"];
    }

    // Create the custom description string
    NSString* customDescription = [NSString stringWithFormat:@"SealdException(status=%@, code='%@', id='%@', description='%@', details='%@', raw='%@', nativeStack='%@')",
                                   status, code, idValue, description, details, raw, nativeStack];

    // Store the parsed values and the custom description in userInfo
    NSMutableDictionary* userInfo = [NSMutableDictionary dictionaryWithDictionary:@{
                                         @"status": status ?: [NSNull null],
                                         @"code": code,
                                         @"id": idValue,
                                         @"description": description ?: [NSNull null],
                                         @"details": details ?: [NSNull null],
                                         @"raw": raw ?: [NSNull null],
                                         @"nativeStack": nativeStack ?: [NSNull null],
                                         NSLocalizedDescriptionKey: customDescription
                                     }];

    *errorPtr = [NSError errorWithDomain:SealdErrorDomain code:SealdErrorCodeSealdError userInfo:userInfo];
}

SealdSdkInternalsMobile_sdkStringArray* arrayToStringArray(const NSArray<NSString*>* stringArray) {
    SealdSdkInternalsMobile_sdkStringArray* result = [[SealdSdkInternalsMobile_sdkStringArray alloc] init];
    for (NSString* string in stringArray) {
        result = [result add:string];
    }

    return result;
}

NSArray<NSString*>* stringArrayToArray(SealdSdkInternalsMobile_sdkStringArray* stringArray) {
    NSMutableArray<NSString*>* result = [NSMutableArray arrayWithCapacity:[stringArray size]];
    for (int i = 0; i < [stringArray size]; i++) {
        [result addObject:[stringArray get:i]];
    }
    return result;
}

@implementation SealdClearFile
- (instancetype) initWithFilename:(NSString*)filename
                        messageId:(NSString*)messageId
                      fileContent:(NSData*)fileContent
{
    self = [super init];
    if (self) {
        _filename = filename;
        _messageId = messageId;
        _fileContent = fileContent;
    }
    return self;
}
@end

@implementation SealdAccountInfo
- (instancetype) initWithUserId:(NSString*)userId
                       deviceId:(NSString*)deviceId
                  deviceExpires:(NSDate*)deviceExpires
{
    self = [super init];
    if (self) {
        _userId = userId;
        _deviceId = deviceId;
        _deviceExpires = deviceExpires;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkAccountInfo*)accountInfo
{
    if (accountInfo == nil) {
        return nil;
    }
    NSDate* deviceExpires = nil;
    if (accountInfo.deviceExpires != 0) {
        deviceExpires = [NSDate dateWithTimeIntervalSince1970:accountInfo.deviceExpires];
    }
    return [[SealdAccountInfo alloc] initWithUserId:accountInfo.userId deviceId:accountInfo.deviceId deviceExpires:deviceExpires];
}
@end

@implementation SealdCreateSubIdentityResponse
- (instancetype) initWithDeviceId:(NSString*)deviceId
                        backupKey:(NSData*)backupKey
{
    self = [super init];
    if (self) {
        _deviceId = deviceId;
        _backupKey = backupKey;
    }
    return self;
}
@end

@implementation SealdBeardError
- (instancetype) initWithId:(NSString*)errorId
                       code:(NSString*)code
{
    self = [super init];
    if (self) {
        _errorId = errorId;
        _code = code;
    }
    return self;
}
@end

@implementation SealdConnectorTypeValue
- (instancetype) initWithType:(NSString*)type
                        value:(NSString*)value
{
    self = [super init];
    if (self) {
        _type = type;
        _value = value;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkConnectorTypeValue*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkConnectorTypeValue* res = [[SealdSdkInternalsMobile_sdkConnectorTypeValue alloc] init];
    res.type = self.type;
    res.value = self.value;
    return res;
}
+ (SealdSdkInternalsMobile_sdkConnectorTypeValueArray*) toMobileSdkArray:(NSArray<SealdConnectorTypeValue*>*)connectorsArray
{
    SealdSdkInternalsMobile_sdkConnectorTypeValueArray* result = [[SealdSdkInternalsMobile_sdkConnectorTypeValueArray alloc] init];
    for (SealdConnectorTypeValue* connector in connectorsArray) {
        result = [result add:[connector toMobileSdk]];
    }
    return result;
}
@end

@implementation SealdConnector
- (instancetype) initWithSealdId:(NSString*)sealdId
                            type:(NSString*)type
                           value:(NSString*)value
                     connectorId:(NSString*)connectorId
                           state:(NSString*)state
{
    self = [super init];
    if (self) {
        _sealdId = sealdId;
        _type = type;
        _value = value;
        _connectorId = connectorId;
        _state = state;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkConnector*)c
{
    return [[SealdConnector alloc] initWithSealdId:c.sealdId type:c.type value:c.value connectorId:c.id_ state:c.state];
}
+ (NSArray<SealdConnector*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkConnectorsArray*)connectorsArray
{
    NSMutableArray<SealdConnector*>* result = [NSMutableArray arrayWithCapacity:[connectorsArray size]];
    for (int i = 0; i < [connectorsArray size]; i++) {
        SealdSdkInternalsMobile_sdkConnector* c = [connectorsArray get:i];
        [result addObject:[SealdConnector fromMobileSdk:c]];
    }
    return result;
}
+ (SealdSdkInternalsMobile_sdkConnectorsArray*) toMobileSdkArray:(NSArray<SealdConnector*>*)connectorsArray
{
    SealdSdkInternalsMobile_sdkConnectorsArray* result = [[SealdSdkInternalsMobile_sdkConnectorsArray alloc] init];
    for (SealdConnector* c in connectorsArray) {
        SealdSdkInternalsMobile_sdkConnector* mobileSdkConnector = [c toMobileSdk];
        result = [result add:mobileSdkConnector];
    }
    return result;
}
- (SealdSdkInternalsMobile_sdkConnector*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkConnector* res = [[SealdSdkInternalsMobile_sdkConnector alloc] init];
    res.sealdId = self.sealdId;
    res.type = self.type;
    res.value = self.value;
    res.id_ = self.connectorId;
    res.state = self.state;
    return res;
}
@end

@implementation SealdPreValidationToken
- (instancetype) initWithDomainValidationKeyId:(NSString*)domainValidationKeyId
                                         nonce:(NSString*)nonce
                                         token:(NSString*)token
{
    if (self = [super init]) {
        _domainValidationKeyId = domainValidationKeyId;
        _nonce = nonce;
        _token = token;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkPreValidationToken*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkPreValidationToken* res = [[SealdSdkInternalsMobile_sdkPreValidationToken alloc] init];
    res.domainValidationKeyId = self.domainValidationKeyId;
    res.nonce = self.nonce;
    res.token = self.token;
    return res;
}
@end

@implementation SealdMassReencryptOptions
- (instancetype) init
{
    self = [super init];
    if (self) {
        _retries = 3;
        _retrieveBatchSize = 1000;
        _waitBetweenRetries = 3.0;
        _waitProvisioning = YES;
        _waitProvisioningTime = 5.0;
        _waitProvisioningTimeMax = 10.0;
        _waitProvisioningTimeStep = 1.0;
        _waitProvisioningRetries = 100;
        _forceLocalAccountUpdate = NO;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkMassReencryptOptions*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkMassReencryptOptions* res = [[SealdSdkInternalsMobile_sdkMassReencryptOptions alloc] init];
    res.retries = self.retries;
    res.retrieveBatchSize = self.retrieveBatchSize;
    res.waitBetweenRetries = (int64_t)(self.waitBetweenRetries * 1000);
    res.waitProvisioning = self.waitProvisioning;
    res.waitProvisioningTime = (int64_t)(self.waitProvisioningTime * 1000);
    res.waitProvisioningTimeMax = (int64_t)(self.waitProvisioningTimeMax * 1000);
    res.waitProvisioningTimeStep = (int64_t)(self.waitProvisioningTimeStep * 1000);
    res.waitProvisioningRetries = self.waitProvisioningRetries;
    res.forceLocalAccountUpdate = self.forceLocalAccountUpdate;
    return res;
}
@end

@implementation SealdMassReencryptResponse
- (instancetype) initWithReencrypted:(NSInteger)reencrypted
                              failed:(NSInteger)failed
{
    self = [super init];
    if (self) {
        _reencrypted = reencrypted;
        _failed = failed;
    }
    return self;
}
+ (SealdMassReencryptResponse*) fromMobileSdk:(SealdSdkInternalsMobile_sdkMassReencryptResponse*)d
{
    return [[SealdMassReencryptResponse alloc] initWithReencrypted:d.reencrypted failed:d.failed];
}
@end

@implementation SealdDeviceMissingKeys
- (instancetype) initWithDeviceId:(NSString*)deviceId
{
    self = [super init];
    if (self) {
        _deviceId = deviceId;
    }
    return self;
}
+ (SealdDeviceMissingKeys*) fromMobileSdk:(SealdSdkInternalsMobile_sdkDeviceMissingKeys*)d
{
    return [[SealdDeviceMissingKeys alloc] initWithDeviceId:d.deviceId];
}
+ (NSArray<SealdDeviceMissingKeys*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkDevicesMissingKeysArray*)array
{
    NSMutableArray<SealdDeviceMissingKeys*>* result = [NSMutableArray arrayWithCapacity:[array size]];
    for (int i = 0; i < [array size]; i++) {
        [result addObject:[SealdDeviceMissingKeys fromMobileSdk:[array get:i]]];
    }
    return result;
}
@end

@implementation SealdActionStatus
+ (NSDictionary<NSString*,SealdActionStatus*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkActionStatusArray*)array
{
    NSMutableDictionary* dictionary = [[NSMutableDictionary alloc] init];
    for (NSInteger i = 0; i < [array size]; i++) {
        SealdSdkInternalsMobile_sdkActionStatus* goEl = [array get:i];
        SealdActionStatus* as = [[SealdActionStatus alloc] init];
        as.success = goEl.success;
        as.errorCode = goEl.errorCode;
        as.result = goEl.result;
        [dictionary setObject:as forKey:goEl.id_];
    }

    return dictionary;
}
@end

@implementation SealdRevokeResult
- (instancetype) initWithRecipients:(NSDictionary<NSString*,SealdActionStatus*>*)recipients
                      proxySessions:(NSDictionary<NSString*,SealdActionStatus*>*)proxySessions
{
    self = [super init];
    if (self) {
        _recipients = recipients;
        _proxySessions = proxySessions;
    }
    return self;

}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkRevokeResult*)revokeResult
{
    return [[SealdRevokeResult alloc] initWithRecipients:[SealdActionStatus fromMobileSdkArray:revokeResult.recipients]
                                           proxySessions:[SealdActionStatus fromMobileSdkArray:revokeResult.proxySessions]];
}
@end

@implementation SealdRecipientRights
- (instancetype) initWithRead:(BOOL)read
                      forward:(BOOL)forward
                       revoke:(BOOL)revoke
{
    self = [super init];
    if (self) {
        _read = read;
        _forward = forward;
        _revoke = revoke;
    }
    return self;
}
- (instancetype) initWithDefaultRights
{
    self = [super init];
    if (self) {
        _read = YES;
        _forward = YES;
        _revoke = NO;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkRecipientRights*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkRecipientRights* res = [[SealdSdkInternalsMobile_sdkRecipientRights alloc] init];
    res.read = self.read;
    res.forward = self.forward;
    res.revoke = self.revoke;
    return res;
}
@end

@implementation SealdRecipientWithRights
- (instancetype) initWithRecipientId:(NSString*)recipientId
                              rights:(SealdRecipientRights*_Nullable)rights
{
    self = [super init];
    if (self) {
        _recipientId = recipientId;
        _rights = rights;
    }
    return self;
}
- (instancetype) initWithRecipientId:(NSString*)recipientId
{
    self = [super init];
    if (self) {
        _recipientId = recipientId;
        _rights = NULL;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkRecipientWithRights*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkRecipientWithRights* res = [[SealdSdkInternalsMobile_sdkRecipientWithRights alloc] init];
    res.recipientId = self.recipientId;
    res.rights = [self.rights toMobileSdk];
    return res;
}
+ (SealdSdkInternalsMobile_sdkRecipientsWithRightsArray*) toMobileSdkArray:(NSArray<SealdRecipientWithRights*>*)rwrArray
{
    SealdSdkInternalsMobile_sdkRecipientsWithRightsArray* result = [[SealdSdkInternalsMobile_sdkRecipientsWithRightsArray alloc] init];
    for (SealdRecipientWithRights* rwr in rwrArray) {
        result = [result add:[rwr toMobileSdk]];
    }
    return result;
}
@end

@implementation SealdEncryptionSessionRetrievalDetails
- (instancetype) initWithFlow:(SealdEncryptionSessionRetrievalFlow)flow
                      groupId:(NSString*)groupId
               proxySessionId:(NSString*)proxySessionId
                    fromCache:(BOOL)fromCache
{
    self = [super init];
    if (self) {
        _flow = flow;
        _groupId = groupId;
        _proxySessionId = proxySessionId;
        _fromCache = fromCache;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkEncryptionSessionRetrievalDetails*)details
{
    return [[SealdEncryptionSessionRetrievalDetails alloc] initWithFlow:(SealdEncryptionSessionRetrievalFlow)details.flow
                                                                groupId:(details.groupId.length > 0 ? details.groupId : nil)
                                                         proxySessionId:(details.proxySessionId.length > 0 ? details.proxySessionId : nil)
                                                              fromCache:details.fromCache
    ];
}
@end

@implementation SealdGetSigchainResponse
- (instancetype) initWithSigchainHash:(NSString*)sigchainHash
                             position:(NSInteger)position
{
    self = [super init];
    if (self) {
        _sigchainHash = sigchainHash;
        _position = position;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkGetSigchainResponse*)nativeResp
{
    return [[SealdGetSigchainResponse alloc] initWithSigchainHash:nativeResp.hash position:nativeResp.position];
}
@end

@implementation SealdCheckSigchainResponse
- (instancetype) initWithFound:(BOOL)found
                      position:(NSInteger)position
                  lastPosition:(NSInteger)lastPosition
{
    self = [super init];
    if (self) {
        _found = found;
        _position = position;
        _lastPosition = lastPosition;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkCheckSigchainResponse*)nativeResp
{
    return [[SealdCheckSigchainResponse alloc] initWithFound:nativeResp.found
                                                    position:nativeResp.position
                                                lastPosition:nativeResp.lastPosition];
}
@end

@implementation SealdTmrAuthFactor
- (instancetype) initWithValue:(NSString*)value
                          type:(NSString*)type
{
    if (self = [super init]) {
        _value = value;
        _type = type;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkAuthFactor*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkAuthFactor* af = [[SealdSdkInternalsMobile_sdkAuthFactor alloc] init];
    af.value = self.value;
    af.type = self.type;
    return af;
}
@end

@implementation SealdTmrRecipientWithRights
- (instancetype) initWithAuthFactor:(SealdTmrAuthFactor*)authFactor
                  overEncryptionKey:(NSData*)overEncryptionKey
                             rights:(SealdRecipientRights*_Nullable)rights
{
    self = [super init];
    if (self) {
        _authFactor = authFactor;
        _rights = rights;
        _overEncryptionKey = overEncryptionKey;
    }
    return self;
}
- (instancetype) initWithAuthFactor:(SealdTmrAuthFactor*)authFactor
                  overEncryptionKey:(NSData*)overEncryptionKey
{
    self = [super init];
    if (self) {
        _authFactor = authFactor;
        _rights = NULL;
        _overEncryptionKey = overEncryptionKey;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkTmrRecipientWithRights*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkTmrRecipientWithRights* res = [[SealdSdkInternalsMobile_sdkTmrRecipientWithRights alloc] init];
    res.authFactor = [self.authFactor toMobileSdk];
    res.rights = [self.rights toMobileSdk];
    res.overEncryptionKey = self.overEncryptionKey;
    return res;
}
+ (SealdSdkInternalsMobile_sdkTmrRecipientWithRightsArray*) toMobileSdkArray:(NSArray<SealdTmrRecipientWithRights*>*)rArray
                                                                       error:(NSError*_Nullable*)error
{
    SealdSdkInternalsMobile_sdkTmrRecipientWithRightsArray* result = [[SealdSdkInternalsMobile_sdkTmrRecipientWithRightsArray alloc] init];
    for (SealdTmrRecipientWithRights* tmrR in rArray) {
        result = [result add:[tmrR toMobileSdk]];
    }
    return result;
}
@end

@implementation SealdTmrAccessesRetrievalFilters
- (instancetype) initWithCreatedById:(NSString*)createdById
                         tmrAccessId:(NSString*)tmrAccessId
{
    if (self = [super init]) {
        _createdById = createdById;
        _tmrAccessId = tmrAccessId;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkTmrAccessesRetrievalFilters*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkTmrAccessesRetrievalFilters* res = [[SealdSdkInternalsMobile_sdkTmrAccessesRetrievalFilters alloc] init];
    res.createdById = self.createdById;
    res.tmrAccessId = self.tmrAccessId;
    return res;
}
@end

@implementation SealdTmrAccessesConvertFilters
- (instancetype) initWithSessionId:(NSString*)sessionId
                       createdById:(NSString*)createdById
                       tmrAccessId:(NSString*)tmrAccessId
{
    if (self = [super init]) {
        _sessionId = sessionId;
        _createdById = createdById;
        _tmrAccessId = tmrAccessId;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkTmrAccessesConvertFilters*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkTmrAccessesConvertFilters* res = [[SealdSdkInternalsMobile_sdkTmrAccessesConvertFilters alloc] init];
    res.sessionId = self.sessionId;
    res.createdById = self.createdById;
    res.tmrAccessId = self.tmrAccessId;
    return res;
}
@end

@implementation SealdConvertTmrAccessesResult
- (instancetype) initWithStatus:(NSString*)status
                      succeeded:(NSInteger)succeeded
                        errored:(NSInteger)errored
                      converted:(NSArray<NSString*>*)converted
{
    self = [super init];
    if (self) {
        _status = status;
        _succeeded = succeeded;
        _errored = errored;
        _converted = converted;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkConvertTmrAccessesResponse*)nativeResp
{
    return [[SealdConvertTmrAccessesResult alloc] initWithStatus:nativeResp.status
                                                       succeeded:nativeResp.succeeded
                                                         errored:nativeResp.errored
                                                       converted:stringArrayToArray(nativeResp.converted)];
}
@end

@implementation SealdGroupTmrTemporaryKey
- (instancetype) initWithKeyId:(NSString*)keyId
                       groupId:(NSString*)groupId
                       isAdmin:(BOOL)isAdmin
                   createdById:(NSString*)createdById
                       created:(NSTimeInterval)created
                authFactorType:(NSString*)authFactorType
{
    self = [super init];
    if (self) {
        _keyId = keyId;
        _groupId = groupId;
        _isAdmin = isAdmin;
        _createdById = createdById;
        _created = &created;
        _authFactorType = authFactorType;
    }
    return self;
}
+ (instancetype) fromMobileSdk:(SealdSdkInternalsMobile_sdkGroupTMRTemporaryKey*)nativeResp
{
    SealdGroupTmrTemporaryKey* resp = [[SealdGroupTmrTemporaryKey alloc] initWithKeyId:nativeResp.keyId
                                                                               groupId:nativeResp.groupId
                                                                               isAdmin:nativeResp.isAdmin
                                                                           createdById:nativeResp.createdById
                                                                               created:nativeResp.created
                                                                        authFactorType:nativeResp.authFactorType];
    return resp;
}
+ (NSArray<SealdGroupTmrTemporaryKey*>*) fromMobileSdkArray:(SealdSdkInternalsMobile_sdkGroupTMRTemporaryKeyArray*)nativeArray
{
    NSMutableArray<SealdGroupTmrTemporaryKey*>* localArray = [NSMutableArray arrayWithCapacity:[nativeArray size]];
    for (int i = 0; i < [nativeArray size]; i++) {
        [localArray addObject:[SealdGroupTmrTemporaryKey fromMobileSdk:[nativeArray get:i]]];
    }
    return localArray;
}
@end

@implementation SealdListedGroupTMRTemporaryKeys
- (instancetype) initWithNbPage:(NSInteger)nbPage
                           keys:(NSArray<SealdGroupTmrTemporaryKey*>*)keys
{
    self = [super init];
    if (self) {
        _nbPage = nbPage;
        _keys = keys;
    }
    return self;
}
+ (SealdListedGroupTMRTemporaryKeys*) fromMobileSdk:(SealdSdkInternalsMobile_sdkListedGroupTMRTemporaryKeys*)nativeListResponse
{
    NSArray<SealdGroupTmrTemporaryKey*>* localArray = [SealdGroupTmrTemporaryKey fromMobileSdkArray:nativeListResponse.keys];
    return [[SealdListedGroupTMRTemporaryKeys alloc] initWithNbPage:nativeListResponse.nbPage keys:localArray];
}
@end

@implementation SealdSearchGroupTMRTemporaryKeys
- (instancetype) initWithGroupId:(NSString*)groupId
                            page:(NSInteger)page
                             all:(BOOL)all
{
    self = [super init];
    if (self) {
        _groupId = groupId;
        _page = page;
        _all = all;
    }
    return self;
}
- (SealdSdkInternalsMobile_sdkSearchGroupTMRTemporaryKeysOpts*) toMobileSdk
{
    SealdSdkInternalsMobile_sdkSearchGroupTMRTemporaryKeysOpts* res = [[SealdSdkInternalsMobile_sdkSearchGroupTMRTemporaryKeysOpts alloc] init];
    res.groupId = self.groupId;
    res.page = self.page;
    res.all = self.all;
    return res;
}
@end
