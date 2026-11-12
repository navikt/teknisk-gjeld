plugins {
    kotlin("jvm") version "2.4.21"
    kotlin("plugin.serialization") version "2.4.21"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("com.google.cloud:libraries-bom:26.93.0"))
    implementation("com.google.cloud:google-cloud-bigquery")
    implementation("com.google.auth:google-auth-library-oauth2-http")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
}

application {
    mainClass.set("no.nav.tekniskgjeld.MainKt")
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED")
}
