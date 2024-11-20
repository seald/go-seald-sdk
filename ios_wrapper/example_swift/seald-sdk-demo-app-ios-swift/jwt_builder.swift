//
//  jwt_builder.swift
//  seald-sdk-demo-app-ios-swift
//
//  Created by Clement on 13/03/2023.
//  Copyright © 2023 Seald SAS. All rights reserved.
//

import Foundation
import JWTKit

class JWTBuilder {
    let JWTSharedSecretId: String
    let JWTSharedSecret: String
    let keys: JWTKeyCollection

    init(JWTSharedSecretId: String, JWTSharedSecret: String) {
        self.JWTSharedSecretId = JWTSharedSecretId
        self.JWTSharedSecret = JWTSharedSecret
        self.keys = JWTKeyCollection()

        // Add the HMAC signing key to the collection
        Task {
            await keys.add(
                hmac: HMACKey(stringLiteral: JWTSharedSecret),
                digestAlgorithm: .sha256,
                kid: JWKIdentifier(string: JWTSharedSecretId)
            )
        }
    }

    enum JWTPermission: String {
        case all = "-1"
        case anonymousCreateMessage = "0"
        case anonymousFindKey = "1"
        case anonymousFindSigchain = "2"
        case joinTeam = "3"
        case addConnector = "4"
    }

    struct SignupPayload: JWTPayload {
        let iss: String
        let jti: String
        let iat: Date
        let join_team: Bool // swiftlint:disable:this identifier_name
        let scopes: String

        func verify(using key: some JWTAlgorithm) throws {}
    }

    struct ConnectorPayload: JWTPayload {
        let iss: String
        let jti: String
        let iat: Date
        let connector_add: [String: String] // swiftlint:disable:this identifier_name
        let scopes: String

        func verify(using key: some JWTAlgorithm) throws {}
    }

    func signupJWT() async throws -> String {
        let payload = SignupPayload(
            iss: JWTSharedSecretId,
            jti: UUID().uuidString,
            iat: Date(),
            join_team: true,
            scopes: JWTPermission.joinTeam.rawValue
        )

        return try await keys.sign(payload)
    }

    func connectorJWT(customUserId: String, appId: String) async throws -> String {
        let payload = ConnectorPayload(
            iss: JWTSharedSecretId,
            jti: UUID().uuidString,
            iat: Date(),
            connector_add: ["type": "AP", "value": "\(customUserId)@\(appId)"],
            scopes: JWTPermission.addConnector.rawValue
        )

        return try await keys.sign(payload)
    }
}
