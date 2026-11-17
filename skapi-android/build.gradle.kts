import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish")
}

android {
    namespace = "com.skapi.android"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
    }
}

dependencies {
    api(project(":skapi"))
}

// Maven Central (central.sonatype.com). Release: ./gradlew publishAndReleaseToMavenCentral
// Credentials and the signing key never go in this project: see PUBLISHING.md.
mavenPublishing {
    configure(AndroidSingleVariantLibrary(variant = "release", sourcesJar = true, publishJavadocJar = true))
    coordinates("com.skapi", "skapi-android", project.version.toString())
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    pom {
        name.set("skapi-android")
        description.set("Android helpers for skapi-kotlin: Keystore-sealed session storage, a device key store for encryption, and app lifecycle hooks.")
        inceptionYear.set("2026")
        url.set("https://github.com/broadwayinc/skapi-kotlin")
        licenses {
            license {
                name.set("Apache-2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("broadwayinc")
                name.set("broadway Inc.")
                url.set("https://www.skapi.com")
            }
        }
        scm {
            url.set("https://github.com/broadwayinc/skapi-kotlin")
            connection.set("scm:git:https://github.com/broadwayinc/skapi-kotlin.git")
            developerConnection.set("scm:git:ssh://git@github.com/broadwayinc/skapi-kotlin.git")
        }
    }
}
