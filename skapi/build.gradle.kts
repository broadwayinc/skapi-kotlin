import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    `java-library`
    id("com.vanniktech.maven.publish")
}

// Published as com.skapi:skapi-kotlin
base {
    archivesName.set("skapi-kotlin")
}

// Java 8 bytecode, so the same jar runs on Android (minSdk 24) and on any JVM 8 or later.
java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        freeCompilerArgs.add("-Xjdk-release=1.8")
    }
    explicitApi()
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}

tasks.jar {
    manifest {
        attributes("Implementation-Title" to "skapi-kotlin", "Implementation-Version" to project.version)
    }
}

// Maven Central (central.sonatype.com). Release: ./gradlew publishAndReleaseToMavenCentral
// Credentials and the signing key never go in this project: see PUBLISHING.md.
mavenPublishing {
    // Sources jar, plus an empty javadoc jar: Maven Central requires one, and the API docs live on the docs site.
    configure(KotlinJvm(javadocJar = JavadocJar.Empty(), sourcesJar = true))
    coordinates("com.skapi", "skapi-kotlin", project.version.toString())
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    pom {
        name.set("skapi-kotlin")
        description.set("Skapi client SDK for Kotlin and the JVM: sign-in, users, a database, files, realtime and client-side encryption.")
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
