//
//  ssks_backend.swift
//  SealdSDK demo app ios swift
//
//  Created by Seald on 02/05/2023.
//

import Foundation
import SealdSdk

struct ChallengeResp: Decodable {
    let sessionId: String
    let mustAuthenticate: Bool
}

class SSKSBackend {
    let keyStorageURL: String
    let appId: String
    let appKey: String

    init(keyStorageURL: String, appId: String, appKey: String) {
        self.keyStorageURL = keyStorageURL
        self.appId = appId
        self.appKey = appKey
    }

    enum SSKSBackendError: Error {
        case invalidURL(String)
        case networkError(String)
    }

    private func post(endpoint: String, requestBody: Data) async throws -> Data {
        guard let url = URL(string: keyStorageURL + endpoint) else {
            throw SSKSBackendError.invalidURL(keyStorageURL + endpoint)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = requestBody
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue(appKey, forHTTPHeaderField: "X-SEALD-APIKEY")
        request.addValue(appId, forHTTPHeaderField: "X-SEALD-APPID")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            print("Error: \(response)")
            print("Error data: \(String(data: data, encoding: .utf8)!)")
            let error = NSError(domain: NSURLErrorDomain, code: NSURLErrorBadServerResponse, userInfo: nil)
            throw SSKSBackendError.networkError(error.localizedDescription)
        }
        print("post data: \(String(data: data, encoding: .utf8)!)")
        return data // String(data: data, encoding: .utf8)!
    }

    func challengeSend(
        userId: String,
        authFactor: SealdTmrAuthFactor,
        createUser: Bool,
        forceAuth: Bool,
        fakeOtp: Bool = false
    ) async throws -> ChallengeResp {
        let jsonAuthFactor: [String: Any] = [
            "type": authFactor.type,
            "value": authFactor.value
            ]
        let jsonObject: [String: Any] = [
                "user_id": userId,
                "auth_factor": jsonAuthFactor,
                "create_user": createUser,
                "force_auth": forceAuth,
                "fake_otp": fakeOtp
            ]
        let jsonData = try JSONSerialization.data(withJSONObject: jsonObject)
        let jsonString = String(data: jsonData, encoding: .utf8)!

        let resp = try await post(endpoint: "tmr/back/challenge_send/", requestBody: jsonString.data(using: .utf8)!)

        // the JSON uses snake_case
        let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
        let challResp: ChallengeResp = try decoder.decode(ChallengeResp.self, from: resp)

        return challResp
    }
}
