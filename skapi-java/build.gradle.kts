import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    `java-library`
    id("com.vanniktech.maven.publish")
}

// Published as com.skapi:skapi-java
base {
    archivesName.set("skapi-java")
}

// Java 8 bytecode, the same as skapi-kotlin, so it runs on Android (minSdk 24) and on any JVM 8 or later.
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
    // skapi-kotlin brings kotlinx-coroutines-core (CompletableFuture bridge included) and kotlinx-serialization-json.
    api(project(":skapi"))
}

tasks.jar {
    manifest {
        attributes("Implementation-Title" to "skapi-java", "Implementation-Version" to project.version)
    }
}

// Maven Central (central.sonatype.com). Release: ./gradlew publishAndReleaseToMavenCentral
// Credentials and the signing key never go in this project: see PUBLISHING.md.
mavenPublishing {
    // Sources jar, plus an empty javadoc jar: Maven Central requires one, and the API docs live on the docs site.
    configure(KotlinJvm(javadocJar = JavadocJar.Empty(), sourcesJar = true))
    coordinates("com.skapi", "skapi-java", project.version.toString())
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    pom {
        name.set("skapi-java")
        description.set("Java API for the Skapi client SDK: CompletableFuture methods and plain Java maps and lists, on top of skapi-kotlin.")
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
