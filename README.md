# ClipOps (Local ADB Edition)

ClipOps is a lightweight, single-package Android application designed to manage clipboard operations (`READ_CLIPBOARD`) for other applications. 

Unlike standard apps that require external tools like **Shizuku** to be pre-installed, **ClipOps (Local ADB Edition)** implements a pure Kotlin/Java TCP ADB Client wrapper inside the app. It uses Android's **Wireless Debugging** loopback interface (`127.0.0.1`) to securely issue shell commands and modify individual package-level `AppOps` permissions.

## Features

1. **Standalone Deployment**: No need to download Shizuku. One APK does it all.
2. **Local Loopback Communication**: Secure Socket client wrapper communicating directly with local system ADB daemon.
3. **App Search & Toggles**: Quick UI toggle switches to disable or enable clipboard access for all third-party applications.
4. **Permanent Authorization cache**: Securely generates and stores RSA authentication keys in your app's private files. No annoying repeat popups.

## Connection Mechanism

Android 11 introduces developer "Wireless Debugging" that maps two dynamic loopback ports:
1. **ADB Port (Connection)**: Located on the main screen of Wireless Debugging (e.g. `127.0.0.1:40129`).
2. **Pairing Port**: Dynamic port hidden inside the pairing dialogue, utilized on first-time authentication.

For security, ClipOps establishes a TCP socket using the ADB connection port. On your first connection, the OS displays an authentication prompt: `"Allow Wireless Debugging?"`. Once accepted, ClipOps caches its custom RSA keys inside `filesDir/` so that it connects silently and immediately on subsequent launches.

Once connected, ClipOps executes secure AppOps commands under the hood:
```bash
cmd appops set <target_package> READ_CLIPBOARD ignore
```

## How to Import & Build

1. Download `/home/max/workspace/clipops.zip` and extract.
2. Open Android Studio (Java 17, Gradle 8.2.2 wrapper).
3. Import the directory.
4. Build and deploy to your Android device (Android 11+ required for local loopback debugging).
