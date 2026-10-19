import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
}

// ---------------------------------------------------------------------------
// Machine-specific values and secrets, looked up in order in:
//   1. -Pname=value
//   2. local.properties (never versioned)
//   3. the environment variable NAME_WITH_UNDERSCORES (obligarth.agent.x -> OBLIGARTH_AGENT_X)
// ---------------------------------------------------------------------------
val localProperties: Properties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

fun setting(name: String): String? =
    ((project.findProperty(name) as String?)
        ?: localProperties.getProperty(name)
        ?: System.getenv(name.replace('.', '_').uppercase()))
        ?.trim()
        ?.takeIf { it.isNotEmpty() }

// ---------------------------------------------------------------------------
// Version: VERSION file, versionCode = major * 10000 + minor * 100 + patch.
// ---------------------------------------------------------------------------
val appVersionName: String = rootProject.file("VERSION").readText().trim()
val appVersionCode: Int = run {
    val m = Regex("""^(\d+)\.(\d+)\.(\d+)$""").matchEntire(appVersionName)
        ?: throw GradleException("VERSION must be MAJOR.MINOR.PATCH, got '$appVersionName'")
    val (major, minor, patch) = m.destructured.toList().map { it.toInt() }
    if (minor > 99 || patch > 99) throw GradleException("VERSION minor/patch must be 0..99, got '$appVersionName'")
    if (major < 1 || major > 20000) throw GradleException("VERSION major must be 1..20000, got '$appVersionName'")
    major * 10000 + minor * 100 + patch
}

// ---------------------------------------------------------------------------
// Compiled trust (spec PB11, RC-2): server host allow-list, pinned APK signers,
// server key pins, optional TLS pins. Lists are comma separated, hashes are
// lowercase SHA-256 hex.
// ---------------------------------------------------------------------------
val hexList = Regex("""^[0-9a-f]{64}(,[0-9a-f]{64})*$""")
val hostList = Regex("""^[a-z0-9.-]+(,[a-z0-9.-]+)*$""")

fun listSetting(name: String, pattern: Regex): String {
    val raw = setting(name)?.lowercase()?.replace(" ", "") ?: return ""
    if (!pattern.matches(raw)) throw GradleException("$name is malformed: '$raw'")
    return raw
}

val releaseHosts = listSetting("obligarth.agent.allowedHosts", hostList)
val debugHosts = listSetting("obligarth.agent.debugAllowedHosts", hostList)
    .ifEmpty { "mdm.example.net,localhost,127.0.0.1,10.0.2.2" }
val releaseSigners = listSetting("obligarth.agent.pinnedSigners", hexList)
val releaseServerKeyPins = listSetting("obligarth.agent.serverKeyPins", hexList)
val debugServerKeyPins = listSetting("obligarth.agent.debugServerKeyPins", hexList)
val tlsPins = listSetting("obligarth.agent.tlsPins", hexList)

fun quoted(value: String) = "\"$value\""

// Release signing: read from local.properties or the environment, never versioned.
// Owners only: no agent ever builds a release (spec §8.1).
val signingKeys = listOf(
    "obligarth.agent.keystore.file", "obligarth.agent.keystore.password",
    "obligarth.agent.key.alias", "obligarth.agent.key.password",
)
val signingValues = signingKeys.associateWith { setting(it) }
val signingReady = signingValues.values.all { it != null }

android {
    namespace = "tools.obli.obligarth.agent"
    compileSdk = 36
    // Pinned to a build-tools version present in the shared (read-only) SDK.
    buildToolsVersion = "36.1.0"

    defaultConfig {
        applicationId = "tools.obli.obligarth.agent"
        minSdk = 24
        // targetSdk 25 on purpose (spec PB8): installable on Android 7 to 14+,
        // Build.SERIAL readable, legacy device-admin policies intact, no Android 8
        // background limits. It can be raised later by an update, never lowered.
        targetSdk = 25
        versionCode = appVersionCode
        versionName = appVersionName
        buildConfigField("String", "TLS_PINS", quoted(tlsPins))
    }

    signingConfigs {
        getByName("debug") {
            // v1 + v2 like the release (RS-10): Android 7.0 reads the signer of an
            // archive reliably from the v1 (JAR) signature.
            enableV1Signing = true
            enableV2Signing = true
        }
        if (signingReady) {
            create("release") {
                storeFile = file(signingValues.getValue("obligarth.agent.keystore.file")!!)
                storePassword = signingValues.getValue("obligarth.agent.keystore.password")
                keyAlias = signingValues.getValue("obligarth.agent.key.alias")
                keyPassword = signingValues.getValue("obligarth.agent.key.password")
                // AGP drops v1 from minSdk 24: forced on (RS-10).
                enableV1Signing = true
                enableV2Signing = true
            }
        }
    }

    buildTypes {
        debug {
            // Never deployed to a fleet.
            applicationIdSuffix = ".debug"
            isMinifyEnabled = false
            buildConfigField("String", "ALLOWED_SERVER_HOSTS", quoted(debugHosts))
            // Debug: the key that signed this very build (the local debug key) is pinned at run time.
            buildConfigField("String", "PINNED_SIGNERS", quoted(""))
            buildConfigField("boolean", "PIN_OWN_SIGNER", "true")
            buildConfigField("String", "SERVER_KEY_PINS", quoted(debugServerKeyPins))
            // Trust on first contact allowed in debug only (spec PB11).
            buildConfigField("boolean", "REQUIRE_SERVER_KEY_PIN", "false")
        }
        release {
            // Not minified: Knox is reached by reflection.
            isMinifyEnabled = false
            buildConfigField("String", "ALLOWED_SERVER_HOSTS", quoted(releaseHosts))
            buildConfigField("String", "PINNED_SIGNERS", quoted(releaseSigners))
            buildConfigField("boolean", "PIN_OWN_SIGNER", "false")
            buildConfigField("String", "SERVER_KEY_PINS", quoted(releaseServerKeyPins))
            buildConfigField("boolean", "REQUIRE_SERVER_KEY_PIN", "true")
            if (signingReady) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    lint {
        // Deliberate targetSdk 25 (spec PB8): the agent is never published on
        // Google Play, whose target level rules these two checks enforce.
        disable += setOf("ExpiredTargetSdkVersion", "OldTargetApi")
        abortOnError = true
    }
}

// A release must carry its compiled trust and its signing key, or it fails
// (spec §8.1, RC-2). Checked when a release task runs, so debug builds are free.
val checkReleaseInputs = tasks.register("checkReleaseInputs") {
    val hosts = releaseHosts
    val signers = releaseSigners
    val keyPins = releaseServerKeyPins
    val missingSigning = signingValues.filterValues { it == null }.keys.toList()
    doLast {
        val missing = buildList {
            if (hosts.isEmpty()) add("obligarth.agent.allowedHosts")
            if (signers.isEmpty()) add("obligarth.agent.pinnedSigners")
            if (keyPins.isEmpty()) add("obligarth.agent.serverKeyPins")
            addAll(missingSigning)
        }
        if (missing.isNotEmpty()) throw GradleException("Release build refused, missing: ${missing.joinToString()}")
    }
}
tasks.matching { it.name == "preReleaseBuild" }.configureEach { dependsOn(checkReleaseInputs) }

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
