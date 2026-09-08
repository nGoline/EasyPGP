plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization") version "2.2.0"
}

/**
 * The CI upload key, supplied through the environment by the release workflow and never stored in
 * the repository or in a properties file. When these are unset — every local build — no signing
 * config is created and `assembleRelease` produces an unsigned build, exactly as it did before.
 * The app signing key itself stays offline: Play App Signing holds it, and this key only
 * authorises uploads.
 */
/**
 * An environment variable, treating blank as absent. GitHub Actions sets a variable mapped from an
 * unset secret to the empty string rather than leaving it out, so a plain null check would let ""
 * through and every fallback below would be dead code.
 */
fun env(name: String): String? = System.getenv(name)?.takeIf { it.isNotBlank() }

val uploadKeystore = env("UPLOAD_KEYSTORE_FILE")?.let(::file)?.takeIf { it.isFile }

android {
    namespace = "com.ngoline.easygpg"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.ngoline.easygpg"
        minSdk = 35
        targetSdk = 36
        versionCode = 7
        versionName = "0.5"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (uploadKeystore != null) {
            create("upload") {
                storeFile = uploadKeystore
                storePassword = env("UPLOAD_KEYSTORE_PASSWORD")
                keyAlias = env("UPLOAD_KEY_ALIAS")
                // A PKCS12 keystore has a single password: keytool cannot give the key one of its
                // own. Only set UPLOAD_KEY_PASSWORD for an old JKS that really does have two.
                keyPassword = env("UPLOAD_KEY_PASSWORD") ?: env("UPLOAD_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            // Keeps the debug build a separate install from the release one. The instrumented
            // tests clear the target app's filesDir, which would otherwise destroy the key rings
            // of anyone running them against a phone carrying their own build.
            applicationIdSuffix = ".debug"
        }
        release {
            // Null off CI, which leaves the build unsigned rather than failing.
            signingConfig = signingConfigs.findByName("upload")
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures {
        viewBinding = true
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }
    // Key-ring helpers used by both the JVM and the instrumented tests.
    sourceSets {
        getByName("test").java.srcDir("src/testShared/java")
        getByName("androidTest").java.srcDir("src/testShared/java")
    }
    packaging {
        resources {
            excludes += "/META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
    kotlin {
        compilerOptions {
            freeCompilerArgs.add("-Xmulti-dollar-interpolation")
        }
    }
}

dependencies {

    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("androidx.lifecycle:lifecycle-livedata-ktx:2.9.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.1")
    implementation("androidx.navigation:navigation-fragment-ktx:2.9.1")
    implementation("androidx.navigation:navigation-ui-ktx:2.9.1")
    implementation("org.bouncycastle:bcpg-jdk18on:1.81")
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    implementation("org.bouncycastle:bcutil-jdk18on:1.81")
    implementation("androidx.preference:preference-ktx:1.2.1")
    implementation("com.yubico.yubikit:android:2.8.1")
    implementation("com.yubico.yubikit:openpgp:2.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    implementation("androidx.security:security-crypto:1.1.0-beta01")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.15.1")
    testImplementation("androidx.test:core-ktx:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}