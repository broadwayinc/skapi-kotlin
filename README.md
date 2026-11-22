# Skapi for Kotlin, Java, Android Development

The [Skapi](https://www.skapi.com) backend for Kotlin, Android and Java: sign users in, keep their sessions, and read and write your project's database. Same API as [skapi-js](https://www.npmjs.com/package/skapi-js), with Kotlin coroutines (or `CompletableFuture` from Java).

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.skapi:skapi-kotlin:2.4.4")
    implementation("com.skapi:skapi-android:2.4.4") // Android apps: session storage, device key store, lifecycle
    implementation("com.skapi:skapi-java:2.4.4")    // Java code: CompletableFuture methods, plain Java maps and lists
}
```

```kotlin
import com.skapi.Skapi
import com.skapi.jsonOf

val skapi = Skapi("<Project ID>") // from your project's Settings page on skapi.com

suspend fun hello() {
    skapi.login("user@example.com", "password")
    val record = skapi.postRecord(
        jsonOf("title" to "Hello"),
        jsonOf("table" to jsonOf("name" to "posts", "access_group" to "public")),
    )
    val posts = skapi.getRecords(jsonOf("table" to jsonOf("name" to "posts", "access_group" to "public")))
}
```

From Java, with skapi-java:

```java
import com.skapi.java.SkapiJava;
import com.skapi.java.SkapiJson;
import java.util.Map;

SkapiJava skapi = new SkapiJava("<Project ID>");

skapi.login("user@example.com", "password").get();
Map<String, Object> record = skapi.postRecord(
    SkapiJson.obj("title", "Hello"),
    SkapiJson.obj("table", SkapiJson.obj("name", "posts", "access_group", "public"))
).get();
// a failed call: get() throws ExecutionException whose getCause() is the SkapiException
```

- Kotlin/JVM 8 or later, and Android 7.0 (API 24) or later. Dependencies: kotlinx-coroutines, kotlinx-serialization-json and OkHttp.
- Every call is a `suspend` function run on `Dispatchers.IO`; failures throw `SkapiException` with the same codes as skapi-js.
- Sign-in uses the same SRP exchange as skapi-js: the password never leaves the device.
- Two-step login with an authenticator app, file attachments, and every query form of skapi-js.
- Realtime messages between users over WebSocket, in groups or one to one.
- Optional encryption of private records on the device, compatible with skapi-js and skapi-py, with "remember this device" through the Android Keystore.

Layout:

- `skapi/`: the core library (`com.skapi`), plain Kotlin/JVM, works on Android and on any JVM.
- `skapi-android/`: `SharedPreferencesStorage`, `AndroidKeystoreDeviceKeyStore` and `SkapiLifecycle` (`com.skapi.android`). Built when `ANDROID_HOME` (or `sdk.dir` in `local.properties`) points at an Android SDK.
- `skapi-java/`: `SkapiJava`, `SkapiJson`, `FetchOptionsBuilder` and `EncryptionOptionsBuilder` (`com.skapi.java`): every `Skapi` method returning a `CompletableFuture`, with `Map<String, Object>` and `List<Object>` in place of kotlinx JSON. Java 8 bytecode, a layer over `skapi/`.

Build: `./gradlew :skapi:jar :skapi-java:jar` (and `./gradlew :skapi-android:assembleRelease` with an Android SDK).

Documentation: https://jvm.skapi.com

License: Apache-2.0, broadway Inc.
