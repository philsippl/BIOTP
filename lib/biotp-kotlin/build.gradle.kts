plugins {
    kotlin("jvm") version "2.0.0"
    `java-library`
    `maven-publish`
}

group = "com.biotp"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}
