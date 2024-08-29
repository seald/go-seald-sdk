# Seald SDK demo app Android

This is a basic app, demonstrating use of the Seald SDK for Android.

You can check the reference documentation at <https://docs.seald.io/sdk/seald-sdk-android/>.

The main file you could be interested in reading is [`./app/src/main/java/io/seald/seald_sdk_demo_app_android/MainActivity.kt`](./app/src/main/java/io/seald/seald_sdk_demo_app_android/MainActivity.kt).

Also, to run the example app, you must copy `./app/src/main/java/io/seald/seald_sdk_demo_app_android/Credentials.kt_template` to `./app/src/main/java/io/seald/seald_sdk_demo_app_android/Credentials.kt`, and set
the values of `API_URL`, `APP_ID`, `JWT_SHARED_SECRET_ID`, `JWT_SHARED_SECRET`, `SSKS_URL` and `SSKS_BACKEND_APP_KEY`.

To get these values, you must create your own Seald team on <https://www.seald.io/create-sdk>. Then, you can get the
values of `API_URL`, `APP_ID`, `JWT_SHARED_SECRET_ID`, and `JWT_SHARED_SECRET`, on the `SDK` tab of the Seald dashboard
settings, and you can get `SSKS_URL` and `SSKS_BACKEND_APP_KEY` on the `SSKS` tab.

Finally, to run from the CLI:

```bash
# Install
./gradlew installDebug

# Run
adb shell am start -n io.seald.seald_sdk_demo_app_android/io.seald.seald_sdk_demo_app_android.MainActivity

# Get logs
adb logcat
```
