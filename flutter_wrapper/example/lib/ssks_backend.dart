import 'package:http/http.dart' as http;
import 'dart:convert';

class ChallengeSendResponse {
  final String sessionId;
  final bool mustAuthenticate;

  ChallengeSendResponse(
      {required this.sessionId, required this.mustAuthenticate});

  factory ChallengeSendResponse.fromJson(Map<String, dynamic> json) {
    return ChallengeSendResponse(
      sessionId: json['session_id'],
      mustAuthenticate: json['must_authenticate'],
    );
  }
}

class SsksBackend {
  final String keyStorageURL;
  final String appId;
  final String appKey;
  final http.Client httpClient;

  SsksBackend(this.keyStorageURL, this.appId, this.appKey)
      : httpClient = http.Client();

  Future<String> post(String endpoint, String jsonBody) async {
    http.Response response = await httpClient.post(
      Uri.parse(keyStorageURL + endpoint),
      headers: {
        "X-SEALD-APPID": appId,
        "X-SEALD-APIKEY": appKey,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: jsonBody,
    );

    print('SsksBackend POST URL: ${keyStorageURL + endpoint}');
    if (response.statusCode != 200) {
      print(
          'HTTP response.code: ${response.statusCode}\nresponse.body: ${response.body}');
      throw Exception('Unexpected HTTP response: ${response.statusCode}');
    }

    String responseBody = response.body;
    print('Response body: $responseBody');
    return responseBody;
  }

  Future<ChallengeSendResponse> challengeSend(
      String userId,
      String authFactorType,
      String authFactorValue,
      bool createUser,
      bool forceAuth,
      {bool fakeOtp = false}) async {
    String jsonObject = jsonEncode({
      "user_id": userId,
      "auth_factor": {
        "type": authFactorType,
        "value": authFactorValue,
      },
      "create_user": createUser,
      "force_auth": forceAuth,
      "fake_otp": fakeOtp,
    });
    String resp = await post("tmr/back/challenge_send/", jsonObject);
    return ChallengeSendResponse.fromJson(json.decode(resp));
  }
}
