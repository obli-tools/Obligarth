// Obligarth bridge agent (channel legacy_agent): device-admin Android agent for
// fleets that cannot be factory reset (no device owner, hence no AMAPI).
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "obligarth-agent-android"

include(":app")
