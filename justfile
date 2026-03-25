# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

server-setup:
    cd lib/biotp-ts && npm install && npm run build
    cd server-ts && npm install && npm run build

server:
    [ -d server-ts/dist ] || just server-setup
    cd server-ts && node dist/server.js

# Run server with attestation checks disabled (for emulator/simulator testing)
server-dev:
    [ -d server-ts/dist ] || just server-setup
    cd server-ts && ALLOW_SIMULATOR=1 node dist/server.js

server-ngrok:
    #!/usr/bin/env bash
    set -euo pipefail

    [ -d server-ts/dist ] || just server-setup

    if ! command -v ngrok >/dev/null 2>&1; then
      echo "ngrok is not installed or not on PATH"
      exit 1
    fi

    if ! curl -sf http://127.0.0.1:4040/api/tunnels >/dev/null 2>&1; then
      nohup ngrok http 8787 >/tmp/humancheck-ngrok.log 2>&1 &
      sleep 1
    fi

    for _ in {1..30}; do
      if curl -sf http://127.0.0.1:4040/api/tunnels >/dev/null 2>&1; then
        break
      fi
      sleep 0.5
    done

    public_url="$(python3 -c "import json, urllib.request; d=json.load(urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels', timeout=2)); t=d.get('tunnels', []); preferred=[x.get('public_url','') for x in t if x.get('public_url','').startswith('https://') and str((x.get('config') or {}).get('addr','')).endswith(':8787')]; fallback=[x.get('public_url','') for x in t if x.get('public_url','').startswith('https://')]; urls=preferred or fallback; print(urls[0] if urls else '')")"

    if [ -z "${public_url}" ]; then
      echo "Could not resolve ngrok https URL from ngrok API"
      exit 1
    fi

    echo "Using PUBLIC_BASE_URL=${public_url}"
    ALLOWED_APP_IDS="${ALLOWED_APP_IDS:-PNXHZNX557.com.ps.humancheck.HumanCheck}"
    cd server-ts
    PUBLIC_BASE_URL="${public_url}" \
    ALLOWED_APP_IDS="${ALLOWED_APP_IDS}" \
    node dist/server.js

# ---------------------------------------------------------------------------
# iOS app
# ---------------------------------------------------------------------------

ios-build:
    xcodebuild -project app/ios/HumanCheck.xcodeproj \
      -scheme HumanCheck \
      -destination 'generic/platform=iOS Simulator' \
      build

ios-test:
    xcodebuild -project app/ios/HumanCheck.xcodeproj \
      -scheme HumanCheck \
      -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
      test

ios-open:
    open app/ios/HumanCheck.xcodeproj

# ---------------------------------------------------------------------------
# Android app
# ---------------------------------------------------------------------------

android-setup:
    cd app/android && gradle wrapper --gradle-version 8.10

android-build:
    cd app/android && ./gradlew :app:assembleDebug

android-run:
    #!/usr/bin/env bash
    set -euo pipefail
    ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"

    just android-build

    # Start emulator if none running
    if ! "$ANDROID_HOME/platform-tools/adb" devices | grep -q 'emulator.*device'; then
      AVD=$("$ANDROID_HOME/emulator/emulator" -list-avds | head -1)
      if [ -z "$AVD" ]; then
        echo "No Android emulator AVDs found. Create one in Android Studio."
        exit 1
      fi
      echo "Starting emulator: $AVD"
      nohup "$ANDROID_HOME/emulator/emulator" -avd "$AVD" -no-snapshot-load >/tmp/humancheck-emulator.log 2>&1 &
      echo "Waiting for emulator to boot..."
      "$ANDROID_HOME/platform-tools/adb" wait-for-device
      "$ANDROID_HOME/platform-tools/adb" shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done'
    fi

    "$ANDROID_HOME/platform-tools/adb" install -r app/android/app/build/outputs/apk/debug/app-debug.apk
    "$ANDROID_HOME/platform-tools/adb" shell am start -n com.humancheck.app/.MainActivity

android-clean:
    cd app/android && ./gradlew clean

# ---------------------------------------------------------------------------
# Libraries
# ---------------------------------------------------------------------------

lib-swift-build:
    cd lib/biotp-swift && swift build

lib-kotlin-build:
    cd lib/biotp-kotlin && gradle build

lib-ts-build:
    cd lib/biotp-ts && npm install && npm run build

lib-py-test:
    cd lib/biotp-py && uv run python -c "from biotp import MasterKey; print('biotp-py OK')"
