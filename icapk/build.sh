#!/bin/sh
# Build the Shizuku-backed APK for the IC POSIX timer LPE.
# Plain SDK tools only (aapt2 / aidl / d8 / zipalign / apksigner): no Gradle,
# so the build stays offline and reproducible on this machine.
set -eu

ROOT=D:/kwork/icapk
SDK=D:/Android/Sdk
BT=$SDK/build-tools/34.0.0
AJ=$SDK/platforms/android-34/android.jar
JDK="C:/Program Files/Java/jdk-17"
JAVAC="$JDK/bin/javac"
JAVA="$JDK/bin/java"
SHZ=$ROOT/shizuku
# provider's ShizukuProvider references moe.shizuku.server.IShizukuApplication,
# which only ships in the api's aidl/shared companions -- without them the
# provider throws NoClassDefFoundError at bind time.
SHZ_JARS="$SHZ/api/classes.jar;$SHZ/provider/classes.jar;$SHZ/aidl/classes.jar;$SHZ/shared/classes.jar"
OUT=$ROOT/build

rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex" "$OUT/apk"

echo "== aidl"
"$BT/aidl.exe" -p "$SDK/platforms/android-34/framework.aidl" \
    -I"$ROOT/aidl" -o"$OUT/gen" \
    "$ROOT/aidl/dev/ic/timerlpe/IIcService.aidl"

echo "== javac"
# No -bootclasspath: android.jar's LambdaMetafactory stub lacks metafactory(),
# so lambdas only compile when javac sees the JDK's java.base as bootstrap.
# android.* still resolves from the classpath; d8 desugars the lambdas.
"$JAVAC" -source 8 -target 8 -Xlint:-options -encoding UTF-8 \
    -classpath "$AJ;$SHZ_JARS" \
    -d "$OUT/classes" \
    $(find "$OUT/gen" "$ROOT/src" -name '*.java')

echo "== d8"
"$JAVA" -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 \
    --lib "$AJ" --min-api 24 --output "$OUT/dex" \
    $(find "$OUT/classes" -name '*.class') \
    "$SHZ/api/classes.jar" "$SHZ/provider/classes.jar" \
    "$SHZ/aidl/classes.jar" "$SHZ/shared/classes.jar"

echo "== aapt2 link"
"$BT/aapt2.exe" link -o "$OUT/apk/base.apk" \
    --manifest "$ROOT/AndroidManifest.xml" \
    -I "$AJ" -A "$ROOT/assets" \
    --min-sdk-version 24 --target-sdk-version 34 \
    --version-code 1 --version-name 0.1

echo "== add dex"
"$JDK/bin/jar" --update --file "$OUT/apk/base.apk" -C "$OUT/dex" classes.dex

echo "== zipalign"
"$BT/zipalign.exe" -f 4 "$OUT/apk/base.apk" "$OUT/apk/aligned.apk"

echo "== sign"
if [ ! -f "$ROOT/debug.keystore" ]; then
    "$JDK/bin/keytool" -genkeypair -keystore "$ROOT/debug.keystore" \
        -storepass android -keypass android -alias ic \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=IC Timer LPE, O=Local, C=CN"
fi
"$JAVA" -jar "$BT/lib/apksigner.jar" sign \
    --ks "$ROOT/debug.keystore" --ks-pass pass:android \
    --key-pass pass:android \
    --out "$OUT/ic-timer-lpe.apk" "$OUT/apk/aligned.apk"

echo "== verify"
"$JAVA" -jar "$BT/lib/apksigner.jar" verify --print-certs \
    "$OUT/ic-timer-lpe.apk" | head -4
ls -l "$OUT/ic-timer-lpe.apk"
