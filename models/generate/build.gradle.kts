// The smithy-rs subproject that generates crates/engine-ses-v2. The recipe
// adds it to a checkout of smithy-rs at the pinned release.
plugins {
    java
    alias(libs.plugins.smithy.gradle.base)
    alias(libs.plugins.smithy.gradle.jar)
}

dependencies {
    implementation(project(":codegen-server"))
    implementation(libs.smithy.aws.traits)
    // The model carries the client's endpoint rules, whose traits and
    // functions must resolve even though a server ignores them.
    implementation(libs.smithy.rules.engine)
    implementation(libs.smithy.aws.endpoints)
}

smithy {
    format.set(false)
}

tasks["jar"].enabled = false
