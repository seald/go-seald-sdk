//
//  jwt_builder.swift
//  seald-sdk-demo-app-ios-swift
//
//  Created by Clement on 13/03/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

import Foundation
import JWT
import CryptoKit

class JWTBuilder {
    let JWTSharedSecretId: String
    let JWTSharedSecret: String
    let JWTAlgorithm: JWTAlgorithm

    init(JWTSharedSecretId: String, JWTSharedSecret: String) {
        self.JWTSharedSecretId = JWTSharedSecretId
        self.JWTSharedSecret = JWTSharedSecret
        self.JWTAlgorithm = JWTAlgorithmFactory.algorithm(byName: "HS256")
    }

    enum JWTPermission: String {
        case all = "-1"
        case anonymousCreateMessage = "0"
        case anonymousFindKey = "1"
        case anonymousFindSigchain = "2"
        case joinTeam = "3"
        case addConnector = "4"
    }

    func signupJWT() -> String {
        let now = Date()

        let headers = ["typ": "JWT"]
        let payload = ["iss": JWTSharedSecretId,
                       "jti": UUID().uuidString,
                       "iat": NSNumber(value: now.timeIntervalSince1970),
                       "join_team": true,
                       "scopes": JWTPermission.joinTeam.rawValue] as [String: Any]
        let token = JWT.encodePayload(
            payload,
            withSecret: JWTSharedSecret,
            withHeaders: headers,
            algorithm: JWTAlgorithm)
        return token!
    }

    func connectorJWT(customUserId: String, appId: String) -> String {
        let now = Date()

        let headers = ["typ": "JWT"]
        let payload = ["iss": JWTSharedSecretId,
                       "jti": UUID().uuidString,
                       "iat": NSNumber(value: now.timeIntervalSince1970),
                       "connector_add": ["type": "AP", "value": "\(customUserId)@\(appId)"],
                       "scopes": JWTPermission.addConnector.rawValue] as [String: Any]
        let token = JWT.encodePayload(
            payload,
            withSecret: JWTSharedSecret,
            withHeaders: headers,
            algorithm: JWTAlgorithm)
        return token!
    }
}
