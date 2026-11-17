pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "skapi-kotlin"

// The core library: plain Kotlin/JVM, works on Android and on any JVM.
include(":skapi")

// The Java API: CompletableFuture methods and plain Java maps and lists, on top of :skapi.
include(":skapi-java")

// Android storage, device key store and app lifecycle helpers. Needs the Android SDK: it is built
// when ANDROID_HOME (or ANDROID_SDK_ROOT, or sdk.dir in local.properties) points at one.
val androidSdk = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
    ?: file("local.properties").takeIf { it.exists() }?.readLines()
        ?.firstOrNull { it.startsWith("sdk.dir=") }?.removePrefix("sdk.dir=")
if (androidSdk != null) {
    include(":skapi-android")
}
