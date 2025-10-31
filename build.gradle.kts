buildscript {
    repositories { mavenCentral() }
    dependencies { classpath("info.solidsoft.gradle.pitest:gradle-pitest-plugin:1.19.0-rc2") }
}

plugins {
    java
    application
    id("info.solidsoft.pitest") version "1.19.0-rc.2"
    id("jacoco")
}

jacoco {
    toolVersion = "0.8.14"
}

allprojects {
    group = "org.bondolo.keystore"
    version = "1.0"
    repositories { mavenCentral() }
}

dependencies {
    implementation("org.jspecify:jspecify:1.0.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.82")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.82")
    testImplementation(platform("org.junit:junit-bom:6.0.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_25
    targetCompatibility = JavaVersion.VERSION_25
}

pitest {
    pitestVersion.set("1.20.7")
    junit5PluginVersion.set("1.2.3")
    threads = 4
    outputFormats = setOf("XML", "HTML")
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        events("failed")
    }
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.register<JavaExec>("keygen") {
    group = "Execution"
    description = "Generates a new key pair and self-signed certificate"
    mainClass.set("org.bondolo.keystore.libexec.KeyGen")
    classpath = sourceSets.main.get().runtimeClasspath
}

tasks.register<JavaExec>("certexport") {
    group = "Execution"
    description = "Exports a certificate from a keystore"
    mainClass.set("org.bondolo.keystore.libexec.CertExport")
    classpath = sourceSets.main.get().runtimeClasspath
}

tasks.register<JavaExec>("certimport") {
    group = "Execution"
    description = "Imports a certificate into a keystore"
    mainClass.set("org.bondolo.keystore.libexec.CertImport")
    classpath = sourceSets.main.get().runtimeClasspath
}

tasks.register<JavaExec>("storelist") {
    group = "Execution"
    description = "Lists the contents of a keystore"
    mainClass.set("org.bondolo.keystore.libexec.StoreList")
    classpath = sourceSets.main.get().runtimeClasspath
}

val generatedSourcesDir = layout.buildDirectory.dir("generated/java")

val generatePasswords by tasks.register("generatePasswords") {
    group = "build"
    description = "Generates Passwords.java from gradle properties."

    val storePasswordProvider = project.providers.gradleProperty("STORE_PASSWORD").orElse("changeit")
    val keyPasswordProvider = project.providers.gradleProperty("KEY_PASSWORD").orElse("changeit")

    inputs.property("storePassword", storePasswordProvider)
    inputs.property("keyPassword", keyPasswordProvider)

    outputs.dir(generatedSourcesDir)

    doLast {
        val passwordsFile = generatedSourcesDir.get().file("org/bondolo/keystore/Passwords.java")
        val storePassword = storePasswordProvider.get()
        val keyPassword = keyPasswordProvider.get()
        passwordsFile.asFile.parentFile.mkdirs()
        passwordsFile.asFile.writeText(
            """
            package org.bondolo.keystore;

            public class Passwords {
                public static final char[] STORE_PASSWORD = "$storePassword".toCharArray();
                public static final char[] KEY_PASSWORD = "$keyPassword".toCharArray();
            }
        """.trimIndent()
        )
    }
}

sourceSets.main.get().java.srcDir(generatedSourcesDir)

tasks.named("compileJava") {
    dependsOn(generatePasswords)
}
