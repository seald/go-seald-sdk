# Seald SDK demo app Flutter

This is a basic app, demonstrating use of the Seald SDK for Flutter for iOS and Android.

You can check the reference documentation at <https://pub.dev/documentation/seald_sdk_flutter/latest/>.

The main file you could be interested in reading is [`./lib/main.dart`](./lib/main.dart).

Before running the app, you have to install the dependencies, with the command `flutter pub get`.

Also, to run the example app, you must copy `./lib/credentials_template.dart` to `./lib/credentials.dart`, and set
the values of `api_url`, `app_id`, `jwt_shared_secret_id`, `jwt_shared_secret`, `ssks_url` and `ssks_backend_app_key`.

To get these values, you must create your own Seald team on <https://www.seald.io/create-sdk>. Then, you can get the
values of `api_url`, `app_id`, `jwt_shared_secret_id`, and `jwt_shared_secret`, on the `SDK` tab of the Seald dashboard
settings, and you can get `ssks_url` and `ssks_backend_app_key` on the `SSKS` tab.

Finally, to run from the CLI, use the command `flutter run`.
