# How to build

## Build AAR

To simply build the AAR:

```bash
# First, you must build Go library (from the root):
export GO386='softfloat'
gomobile bind -target=android -androidapi=21 -javapkg=io.seald.seald_sdk_internals -v -o=./kotlin_wrapper/goLibs/seald-sdk-internals.aar ./mobile_sdk

# Now, build the kotlin wrapper:
cd kotlin_wrapper/
./gradlew assemble
```

This will produce the AAR at the path `kotlin_wrapper/seald_sdk/build/outputs/aar/seald_sdk-release.aar`

## Run example app

From the `example` folder, with an emulator running or a device connected to ADB:

```bash
# Copy the AAR built previously
cp ../seald_sdk/build/outputs/aar/seald_sdk-release.aar ./app/libs/seald_sdk-release.aar

# Install
./gradlew installDebug

# Run
adb shell am start -n io.seald.seald_sdk_demo_app_android/io.seald.seald_sdk_demo_app_android.MainActivity

# Get logs
adb logcat
```

## Build local Maven repository

```bash
./gradlew publishReleasePublicationToLocalRepository -PPACKAGE_VERSION=${VERSION}
```

This will produce a local maven repository at the path `kotlin_wrapper/seald_sdk/build/localRepo/io/seald/seald_sdk_android/${VERSION}/`

## Publish on Maven Central

### Configuration

You must enter the following variables in your `local.properties`:

```
ossrhUsername=USERNAME
ossrhPassword=PASSWORD
sonatypeStagingProfileId=380479b2783bec
signing.keyId=58FF2203
signing.key=SECRET
signing.password=SECRET
```

You can also set these values as environment variables:
```bash
export OSSRH_USERNAME=USERNAME
export OSSRH_PASSWORD=PASSWORD
export SONATYPE_STAGING_PROFILE_ID=380479b2783bec
export SIGNING_KEY_ID=58FF2203
export SIGNING_KEY=SECRET
export SIGNING_PASSWORD=SECRET
```

To get USERNAME and PASSWORD, you must generate a Token : https://central.sonatype.org/publish/generate-token/ 

### Upload & manual release

You can just upload to Maven **but not do the release**, with:
```bash
./gradlew publishReleasePublicationToSonatypeRepository -PPACKAGE_VERSION=${PACKAGE_VERSION}
```

This upload the package to a staging repository on OSSRH.

After this, to release you would have to:
- go to <https://s01.oss.sonatype.org/#stagingRepositories>
- click "Refresh"
- select the repository that was just created
- click "Close" and confirm
- re-click "Refresh"
- click "Release" and confirm

### Upload & automatic release

You can upload & automatically release with:
```bash
./gradlew publishReleasePublicationToSonatypeRepository closeAndReleaseSonatypeStagingRepository -PPACKAGE_VERSION=${PACKAGE_VERSION}
```

The two gradle tasks *have* to be done in a single command, because the
`closeAndReleaseSonatypeStagingRepository` task needs to know the ID of the staging repository
created by the `publishReleasePublicationToSonatypeRepository` task.

:::warning
The package is not available on Maven Central immediately after release. It takes a few minutes (up
to 1h, usually <10min). You can check if the release is available yet by going to
<https://repo1.maven.org/maven2/io/seald/seald_sdk_android/> and looking for the version you have
just released.
:::

### Snapshot

You can upload to the OSSRH Snapshots repository, simply by choosing a PACKAGE_VERSION which ends
with `SNAPSHOT`.

TODO: This DOES NOT work at the moment: getting `Received status code 400 from server: Bad Request`
when trying to upload a snapshot.

# Linting

We are using [KtLint](https://pinterest.github.io/ktlint/) for linting kotlin files, with its standard ruleset.

Two rules are disabled in `.editorconfig`:
- `standard:package-name`: the package is already published, let's not change the package name now ¯\_(ツ)_/¯
- `standard:no-wildcard-imports` : wildcard import is recommended by `kotlinx.coroutines` doc

To install KtLint, follow the documentation: <https://pinterest.github.io/ktlint/1.0.0/install/cli/>.

To verify formatting, you can simply run `ktlint` in the `kotlin_wrapper` directory.

To fix formatting, you can run `ktlint --format` (or `ktlint -F`).

## Build doc

```bash
./gradlew dokkaGfm
./clean-doc.sh
```
