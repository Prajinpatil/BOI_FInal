/**
 * NIRIKSHAK-AI :: Frida Anti-Evasion Instrumentation Script
 * ===========================================================
 *
 * Purpose  : Transparently bypass all common root-detection, emulator-detection,
 *            and analyst-environment-detection techniques employed by Android
 *            banking malware during dynamic sandbox analysis.
 *
 * Target   : MobSF Dynamic Analysis Sandbox / custom Frida-instrumented AOSP
 *            emulator or physical device running a rooted/hooked environment.
 *
 * Spoofed  : Samsung Galaxy S10 (SM-G973F) — Android 10 / API 29
 *            (One of the most common devices in the Indian premium segment)
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │  Bypass Coverage                                                        │
 * │  ─────────────────────────────────────────────────────────────────────  │
 * │  [1]  android.os.Build static field spoofing (SM-G973F profile)         │
 * │  [2]  android.os.Build$VERSION spoofing (API 29 / Android 10)           │
 * │  [3]  java.io.File.exists()   — root / Magisk path hiding               │
 * │  [4]  java.io.File.canExecute() — su binary execution check blocking    │
 * │  [5]  java.lang.Runtime.exec()  — su / busybox command neutralisation   │
 * │  [6]  android.os.SystemProperties.get() — QEMU/Goldfish/debug hide      │
 * │  [7]  android.app.ApplicationPackageManager — Play Store installer spoof │
 * │  [8]  android.telephony.TelephonyManager — Jio / Airtel SIM spoof       │
 * │  [9]  android.telephony.TelephonyManager.getSimState() → SIM_READY      │
 * │  [10] android.provider.Settings$Secure.getInt() — dev-mode / ADB hide   │
 * │  [11] android.provider.Settings$Global.getInt() — dev-mode / ADB hide   │
 * │  [12] java.lang.System.getenv() — env-variable emulator-signature hide  │
 * │  [13] PackageManager.getPackageInfo() — root-app package hiding         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Usage:
 *   frida -U -f com.target.app -l anti_evasion.js --no-pause
 *   frida -H 127.0.0.1:27042 -f com.target.app -l anti_evasion.js
 *   frida-ps -U  (to enumerate running processes)
 *
 * Author   : NIRIKSHAK-AI — Member B (Dynamic Sandbox & Anti-Evasion Engine)
 * Version  : 2.0.0
 * Updated  : 2026-08-14
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════════════════
// § 0 — CONSTANTS & DEVICE PROFILE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Full device profile for Samsung Galaxy S10 (SM-G973F) running Android 10.
 * All values sourced from a production, non-rooted retail unit.
 */
const DEVICE_PROFILE = {
    // ── android.os.Build ──────────────────────────────────────────────────────
    BOARD:          "universal9820",
    BOOTLOADER:     "G973FXXSEFTJ2",
    BRAND:          "samsung",
    CPU_ABI:        "arm64-v8a",
    CPU_ABI2:       "armeabi-v7a",
    DEVICE:         "beyond1lte",
    DISPLAY:        "QP1A.190711.020.G973FXXSEFTJ2",
    FINGERPRINT:    "samsung/starltexx/starlte:10/QP1A.190711.020/G973FXXSEFTJ2:user/release-keys",
    HARDWARE:       "samsungexynos9820",
    HOST:           "SWDD6912",
    ID:             "QP1A.190711.020",
    MANUFACTURER:   "samsung",
    MODEL:          "SM-G973F",
    PRODUCT:        "starltexx",
    RADIO:          "G973FXXSEFTJ2",
    SERIAL:         "R38M80K2YPX",
    TAGS:           "release-keys",
    TYPE:           "user",
    USER:           "dpi",
    // ── android.os.Build$VERSION ─────────────────────────────────────────────
    SDK_INT:        29,
    RELEASE:        "10",
    INCREMENTAL:    "G973FXXSEFTJ2",
    SECURITY_PATCH: "2021-11-01",
    CODENAME:       "REL",
    PREVIEW_SDK_INT: 0,
};

/**
 * All file-system paths that must appear to NOT EXIST during runtime.
 * Covers su binaries, Magisk, Xposed, BusyBox, and emulator device nodes.
 */
const HIDDEN_PATHS = new Set([
    // ── su binary locations ───────────────────────────────────────────────────
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/data/local/tmp/su",
    // ── root management apps (APK paths) ─────────────────────────────────────
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/app/KingRoot.apk",
    "/system/app/Magisk.apk",
    "/system/app/Magisk",
    "/sbin/.magisk",
    "/system/bin/magisk",
    "/data/adb/magisk",
    "/data/adb/magisk.db",
    "/cache/.disable_magisk",
    // ── Xposed Framework markers ──────────────────────────────────────────────
    "/system/framework/XposedBridge.jar",
    "/system/bin/app_process_xposed",
    "/data/data/de.robv.android.xposed.installer",
    // ── BusyBox ───────────────────────────────────────────────────────────────
    "/system/bin/busybox",
    "/system/xbin/busybox",
    "/data/local/tmp/busybox",
    // ── Frida self-detection bypass ───────────────────────────────────────────
    "/proc/self/maps",
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
    // ── QEMU / Android emulator specific device nodes ─────────────────────────
    "/dev/socket/qemud",
    "/dev/qemu_pipe",
    "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace",
    "/system/bin/qemu-props",
    "/dev/goldfish_pipe",
]);

/**
 * Shell commands that must be silently neutralised if executed via Runtime.exec().
 * Malware samples frequently try to probe privilege escalation this way.
 */
const BLOCKED_EXEC_PATTERNS = [
    "su",
    "which su",
    "id",
    "busybox",
    "magisk",
    "getprop ro.build.tags",
    "test-keys",
    "frida-server",
];

/**
 * SystemProperties keys related to QEMU / Goldfish emulator signatures.
 * These must be replaced with values consistent with the spoofed device profile.
 */
const SYSTEM_PROPS_MAP = {
    // ── Emulator / QEMU detection properties ─────────────────────────────────
    "ro.kernel.qemu":               "0",
    "ro.kernel.qemu.gles":          "0",
    "ro.hardware":                  DEVICE_PROFILE.HARDWARE,
    "ro.hardware.goldfish":         "",            // Blank → does not exist
    "ro.hardware.egl":              "mali",        // Mali GPU (Exynos 9820)
    "qemu.sf.lcd_density":          "",
    // ── Build / Release properties ────────────────────────────────────────────
    "ro.build.tags":                "release-keys",
    "ro.build.type":                "user",
    "ro.debuggable":                "0",
    "ro.secure":                    "1",
    "ro.build.selinux":             "1",
    "ro.build.fingerprint":         DEVICE_PROFILE.FINGERPRINT,
    "ro.product.model":             DEVICE_PROFILE.MODEL,
    "ro.product.brand":             DEVICE_PROFILE.BRAND,
    "ro.product.name":              DEVICE_PROFILE.PRODUCT,
    "ro.product.device":            DEVICE_PROFILE.DEVICE,
    "ro.product.manufacturer":      DEVICE_PROFILE.MANUFACTURER,
    // ── ADB / Debug state ─────────────────────────────────────────────────────
    "init.svc.adbd":                "stopped",
    "service.adb.tcp.port":         "",
    "persist.service.adb.enable":   "0",
    // ── Genymotion signatures ─────────────────────────────────────────────────
    "ro.product.vbox_series":       "",
    "ro.genymotion.version":        "",
    // ── BlueStacks signatures ─────────────────────────────────────────────────
    "ro.bluestacks.bp":             "",
    // ── Generic fake-device guard ─────────────────────────────────────────────
    "ro.product.cpu.abi":           "arm64-v8a",
    "ro.product.cpu.abilist":       "arm64-v8a,armeabi-v7a,armeabi",
};

/**
 * Root-management package names that must be invisible to PackageManager queries.
 */
const HIDDEN_PACKAGES = new Set([
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.kingroot.kinguser",
    "com.kingroot.master",
    "com.zhuobie.su",
    "com.mgyun.shua.su",
    "com.xposed.installerx",
    "de.robv.android.xposed.installer",
    "org.meefik.busybox",
]);

// Minimal helper: resolve the canonical path of a java.io.File object safely
function _getPath(fileObj) {
    try { return fileObj.getAbsolutePath(); } catch (_) { return ""; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// § 1 — MAIN JAVA HOOK BLOCK
// ═══════════════════════════════════════════════════════════════════════════════

Java.perform(function () {

    // ─────────────────────────────────────────────────────────────────────────
    // [1] android.os.Build — static field spoofing
    // ─────────────────────────────────────────────────────────────────────────
    (function hookBuild() {
        try {
            const Build = Java.use("android.os.Build");
            const fields = {
                BOARD:        DEVICE_PROFILE.BOARD,
                BOOTLOADER:   DEVICE_PROFILE.BOOTLOADER,
                BRAND:        DEVICE_PROFILE.BRAND,
                DEVICE:       DEVICE_PROFILE.DEVICE,
                DISPLAY:      DEVICE_PROFILE.DISPLAY,
                FINGERPRINT:  DEVICE_PROFILE.FINGERPRINT,
                HARDWARE:     DEVICE_PROFILE.HARDWARE,
                HOST:         DEVICE_PROFILE.HOST,
                ID:           DEVICE_PROFILE.ID,
                MANUFACTURER: DEVICE_PROFILE.MANUFACTURER,
                MODEL:        DEVICE_PROFILE.MODEL,
                PRODUCT:      DEVICE_PROFILE.PRODUCT,
                RADIO:        DEVICE_PROFILE.RADIO,
                SERIAL:       DEVICE_PROFILE.SERIAL,
                TAGS:         DEVICE_PROFILE.TAGS,
                TYPE:         DEVICE_PROFILE.TYPE,
                USER:         DEVICE_PROFILE.USER,
            };

            Object.entries(fields).forEach(([field, value]) => {
                try { Build[field].value = value; } catch (_) { /* read-only on some ROMs */ }
            });

            console.log("[NIRIKSHAK] ✓ [1] Build fields spoofed → Samsung SM-G973F (beyond1lte)");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [1] Build spoofing failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [2] android.os.Build$VERSION — API level & release spoofing
    // ─────────────────────────────────────────────────────────────────────────
    (function hookBuildVersion() {
        try {
            const BV = Java.use("android.os.Build$VERSION");
            try { BV.RELEASE.value          = DEVICE_PROFILE.RELEASE; }         catch (_) {}
            try { BV.INCREMENTAL.value       = DEVICE_PROFILE.INCREMENTAL; }     catch (_) {}
            try { BV.SECURITY_PATCH.value    = DEVICE_PROFILE.SECURITY_PATCH; }  catch (_) {}
            try { BV.CODENAME.value          = DEVICE_PROFILE.CODENAME; }        catch (_) {}
            try { BV.SDK_INT.value           = DEVICE_PROFILE.SDK_INT; }         catch (_) {}
            try { BV.PREVIEW_SDK_INT.value   = DEVICE_PROFILE.PREVIEW_SDK_INT; } catch (_) {}
            console.log("[NIRIKSHAK] ✓ [2] Build.VERSION → Android " +
                        DEVICE_PROFILE.RELEASE + " (API " + DEVICE_PROFILE.SDK_INT + ")");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [2] Build.VERSION spoofing failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [3] java.io.File.exists() — root / emulator path hiding
    // ─────────────────────────────────────────────────────────────────────────
    (function hookFileExists() {
        try {
            const File = Java.use("java.io.File");
            File.exists.implementation = function () {
                const path = _getPath(this);
                if (HIDDEN_PATHS.has(path)) {
                    console.log("[NIRIKSHAK] ✓ [3] File.exists() blocked: " + path);
                    return false;
                }
                return this.exists.call(this);
            };
            console.log("[NIRIKSHAK] ✓ [3] File.exists() hook active (" +
                        HIDDEN_PATHS.size + " paths masked)");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [3] File.exists() hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [4] java.io.File.canExecute() — block su binary execution checks
    // ─────────────────────────────────────────────────────────────────────────
    (function hookFileCanExecute() {
        try {
            const File = Java.use("java.io.File");
            File.canExecute.implementation = function () {
                const path = _getPath(this);
                if (HIDDEN_PATHS.has(path)) {
                    console.log("[NIRIKSHAK] ✓ [4] File.canExecute() blocked: " + path);
                    return false;
                }
                return this.canExecute.call(this);
            };
            console.log("[NIRIKSHAK] ✓ [4] File.canExecute() hook active");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [4] File.canExecute() hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [5] java.lang.Runtime.exec() — su / busybox command neutralisation
    //     Covers both exec(String) and exec(String[]) overloads.
    // ─────────────────────────────────────────────────────────────────────────
    (function hookRuntimeExec() {
        try {
            const Runtime = Java.use("java.lang.Runtime");
            const _isBlocked = (cmd) =>
                cmd && BLOCKED_EXEC_PATTERNS.some(p => cmd.trim().toLowerCase().includes(p));

            // Overload 1: exec(String command)
            Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
                if (_isBlocked(cmd)) {
                    console.log("[NIRIKSHAK] ✓ [5] Runtime.exec(String) neutralised: '" + cmd + "'");
                    return this.exec.call(this, "echo nirikshak_sandbox");
                }
                return this.exec.call(this, cmd);
            };

            // Overload 2: exec(String[] commands)
            Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
                if (cmds && cmds.length > 0 && _isBlocked(cmds[0])) {
                    console.log("[NIRIKSHAK] ✓ [5] Runtime.exec(String[]) neutralised: '" + cmds[0] + "'");
                    return this.exec.call(this, "echo nirikshak_sandbox");
                }
                return this.exec.call(this, cmds);
            };

            // Overload 3: exec(String command, String[] envp)
            Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (cmd, env) {
                if (_isBlocked(cmd)) {
                    console.log("[NIRIKSHAK] ✓ [5] Runtime.exec(String, String[]) neutralised: '" + cmd + "'");
                    return this.exec.call(this, "echo nirikshak_sandbox");
                }
                return this.exec.call(this, cmd, env);
            };

            console.log("[NIRIKSHAK] ✓ [5] Runtime.exec() — all overloads hooked");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [5] Runtime.exec() hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [6] android.os.SystemProperties.get() — QEMU / Goldfish / debug hiding
    //     Intercepts both get(String) and get(String, String) overloads.
    // ─────────────────────────────────────────────────────────────────────────
    (function hookSystemProperties() {
        try {
            const SP = Java.use("android.os.SystemProperties");

            SP.get.overload("java.lang.String").implementation = function (key) {
                if (Object.prototype.hasOwnProperty.call(SYSTEM_PROPS_MAP, key)) {
                    // console.log("[NIRIKSHAK] SP.get(" + key + ") → " + SYSTEM_PROPS_MAP[key]);
                    return SYSTEM_PROPS_MAP[key];
                }
                return this.get.call(this, key);
            };

            SP.get.overload("java.lang.String", "java.lang.String").implementation =
                function (key, def) {
                    if (Object.prototype.hasOwnProperty.call(SYSTEM_PROPS_MAP, key)) {
                        return SYSTEM_PROPS_MAP[key];
                    }
                    return this.get.call(this, key, def);
                };

            console.log("[NIRIKSHAK] ✓ [6] SystemProperties hooked — QEMU/Goldfish/Genymotion signatures hidden");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [6] SystemProperties hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [7] android.app.ApplicationPackageManager — Play Store installer spoof
    //     Also hides root / Xposed management packages from getPackageInfo().
    // ─────────────────────────────────────────────────────────────────────────
    (function hookPackageManager() {
        try {
            const PM = Java.use("android.app.ApplicationPackageManager");

            // Every app appears to have been installed from Google Play
            PM.getInstallerPackageName.implementation = function (pkg) {
                return "com.android.vending";
            };

            console.log("[NIRIKSHAK] ✓ [7] PackageManager.getInstallerPackageName() → com.android.vending");
        } catch (e) {
            // Non-critical: class name differs across Android versions
            console.warn("[NIRIKSHAK] ~ [7] PackageManager hook skipped: " + e.message);
        }

        // ── Hide root-app packages via NameNotFoundException ──────────────────
        try {
            const PM2 = Java.use("android.content.pm.PackageManager");
            const NameNotFoundException = Java.use(
                "android.content.pm.PackageManager$NameNotFoundException"
            );

            PM2.getPackageInfo.overload(
                "java.lang.String", "int"
            ).implementation = function (pkg, flags) {
                if (HIDDEN_PACKAGES.has(pkg)) {
                    console.log("[NIRIKSHAK] ✓ [7] getPackageInfo() hidden for root pkg: " + pkg);
                    throw NameNotFoundException.$new(pkg + " not found (NIRIKSHAK masked)");
                }
                return this.getPackageInfo.call(this, pkg, flags);
            };

            console.log("[NIRIKSHAK] ✓ [7] PackageManager.getPackageInfo() — " +
                        HIDDEN_PACKAGES.size + " root packages hidden");
        } catch (e) {
            console.warn("[NIRIKSHAK] ~ [7] getPackageInfo() hook skipped: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [8] android.telephony.TelephonyManager — SIM / carrier spoofing
    //     Spoofs operator as Jio (primary) with Airtel fallback.
    // ─────────────────────────────────────────────────────────────────────────
    (function hookTelephony() {
        try {
            const TM = Java.use("android.telephony.TelephonyManager");

            // Jio: MCC 404, MNC 20  →  "404020"
            TM.getNetworkOperatorName.implementation = function () { return "Jio"; };
            TM.getNetworkOperator.implementation     = function () { return "404020"; };
            TM.getNetworkCountryIso.implementation   = function () { return "in"; };
            TM.getSimOperatorName.implementation     = function () { return "Jio 4G"; };
            TM.getSimOperator.implementation         = function () { return "404020"; };
            TM.getSimCountryIso.implementation       = function () { return "in"; };

            // ── SIM State: 5 = SIM_STATE_READY ───────────────────────────────
            // [9] Covered here as it belongs to the same class
            try {
                TM.getSimState.overload().implementation = function () {
                    // TelephonyManager.SIM_STATE_READY == 5
                    return 5;
                };
                console.log("[NIRIKSHAK] ✓ [9] TelephonyManager.getSimState() → 5 (SIM_STATE_READY)");
            } catch (e2) {
                console.warn("[NIRIKSHAK] ~ [9] getSimState() hook: " + e2.message);
            }

            console.log("[NIRIKSHAK] ✓ [8] TelephonyManager spoofed → Jio India (MCC:404 MNC:20)");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [8/9] TelephonyManager hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [10] android.provider.Settings$Secure.getInt()
    //      Conceal Developer Mode, ADB, and Mock Locations from being enabled.
    // ─────────────────────────────────────────────────────────────────────────
    (function hookSettingsSecure() {
        try {
            const SettingsSecure = Java.use("android.provider.Settings$Secure");

            const SECURE_OVERRIDE_INT = {
                "development_settings_enabled": 0,
                "adb_enabled":                  0,
                "mock_location":                0,
            };

            // getInt(ContentResolver resolver, String name) — throws if not found
            SettingsSecure.getInt.overload(
                "android.content.ContentResolver", "java.lang.String"
            ).implementation = function (resolver, name) {
                if (Object.prototype.hasOwnProperty.call(SECURE_OVERRIDE_INT, name)) {
                    console.log("[NIRIKSHAK] ✓ [10] Settings.Secure.getInt(" + name + ") → 0");
                    return SECURE_OVERRIDE_INT[name];
                }
                return this.getInt.call(this, resolver, name);
            };

            // getInt(ContentResolver resolver, String name, int def) — with default
            SettingsSecure.getInt.overload(
                "android.content.ContentResolver", "java.lang.String", "int"
            ).implementation = function (resolver, name, def) {
                if (Object.prototype.hasOwnProperty.call(SECURE_OVERRIDE_INT, name)) {
                    console.log("[NIRIKSHAK] ✓ [10] Settings.Secure.getInt(" + name + ", def) → 0");
                    return SECURE_OVERRIDE_INT[name];
                }
                return this.getInt.call(this, resolver, name, def);
            };

            console.log("[NIRIKSHAK] ✓ [10] Settings.Secure.getInt() — developer/ADB settings hidden");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [10] Settings.Secure hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [11] android.provider.Settings$Global.getInt()
    //      Some malware reads Global settings instead of Secure settings.
    // ─────────────────────────────────────────────────────────────────────────
    (function hookSettingsGlobal() {
        try {
            const SettingsGlobal = Java.use("android.provider.Settings$Global");

            const GLOBAL_OVERRIDE_INT = {
                "development_settings_enabled": 0,
                "adb_enabled":                  0,
                "adb_wifi_enabled":             0,
            };

            SettingsGlobal.getInt.overload(
                "android.content.ContentResolver", "java.lang.String"
            ).implementation = function (resolver, name) {
                if (Object.prototype.hasOwnProperty.call(GLOBAL_OVERRIDE_INT, name)) {
                    console.log("[NIRIKSHAK] ✓ [11] Settings.Global.getInt(" + name + ") → 0");
                    return GLOBAL_OVERRIDE_INT[name];
                }
                return this.getInt.call(this, resolver, name);
            };

            SettingsGlobal.getInt.overload(
                "android.content.ContentResolver", "java.lang.String", "int"
            ).implementation = function (resolver, name, def) {
                if (Object.prototype.hasOwnProperty.call(GLOBAL_OVERRIDE_INT, name)) {
                    return GLOBAL_OVERRIDE_INT[name];
                }
                return this.getInt.call(this, resolver, name, def);
            };

            console.log("[NIRIKSHAK] ✓ [11] Settings.Global.getInt() — developer/ADB settings hidden");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [11] Settings.Global hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [12] java.lang.System.getenv() — environment-variable emulator signatures
    //      Emulators sometimes expose ANDROID_EMULATOR_QEMU, QEMU_STDINDEV, etc.
    // ─────────────────────────────────────────────────────────────────────────
    (function hookSystemGetenv() {
        try {
            const System = Java.use("java.lang.System");
            const HIDDEN_ENV_KEYS = new Set([
                "ANDROID_EMULATOR_QEMU",
                "QEMU_STDINDEV",
                "QEMU_AUDIO_DRV",
                "ANDROID_HARDWARE",      // May expose 'goldfish'
            ]);

            System.getenv.overload("java.lang.String").implementation = function (key) {
                if (HIDDEN_ENV_KEYS.has(key)) {
                    console.log("[NIRIKSHAK] ✓ [12] System.getenv(" + key + ") → null");
                    return null;
                }
                return this.getenv.call(this, key);
            };

            console.log("[NIRIKSHAK] ✓ [12] System.getenv() — emulator env variables masked");
        } catch (e) {
            console.error("[NIRIKSHAK] ✗ [12] System.getenv() hook failed: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // [13] Accessibility Service detection bypass
    //      Some banking trojans check if other accessibility services are enabled
    //      as a sign of analysis tooling (e.g., UIAutomator, MonkeyRunner).
    //      We return an empty string so no competing service appears active.
    // ─────────────────────────────────────────────────────────────────────────
    (function hookAccessibilityCheck() {
        try {
            const SettingsSecure = Java.use("android.provider.Settings$Secure");

            const _origGetString = SettingsSecure.getString.overload(
                "android.content.ContentResolver", "java.lang.String"
            );

            _origGetString.implementation = function (resolver, name) {
                if (name === "enabled_accessibility_services") {
                    // Return empty → no accessibility services visible
                    return "";
                }
                return _origGetString.call(this, resolver, name);
            };

            console.log("[NIRIKSHAK] ✓ [13] Accessibility service enumeration blocked");
        } catch (e) {
            console.warn("[NIRIKSHAK] ~ [13] Accessibility hook skipped: " + e.message);
        }
    })();

    // ─────────────────────────────────────────────────────────────────────────
    // Banner — printed after all hooks are installed
    // ─────────────────────────────────────────────────────────────────────────
    console.log("");
    console.log("╔══════════════════════════════════════════════════════════════════╗");
    console.log("║  NIRIKSHAK-AI  ·  Anti-Evasion Frida Script v2.0.0             ║");
    console.log("╠══════════════════════════════════════════════════════════════════╣");
    console.log("║  Device  : Samsung SM-G973F (Galaxy S10 / beyond1lte)          ║");
    console.log("║  Android : 10 (API 29)  ·  Exynos 9820                         ║");
    console.log("║  Carrier : Jio India  (MCC: 404 / MNC: 20)                    ║");
    console.log("║  SIM     : SIM_STATE_READY (5)                                 ║");
    console.log("║  Root    : Hidden  (" + String(HIDDEN_PATHS.size).padStart(2) + " paths masked)                         ║");
    console.log("║  Pkgs    : Hidden  (" + String(HIDDEN_PACKAGES.size).padStart(2) + " root pkgs masked)                   ║");
    console.log("║  Dev Mode: Concealed  (ADB / dev settings → 0)                ║");
    console.log("║  QEMU    : Goldfish / Genymotion / BlueStacks props masked     ║");
    console.log("╚══════════════════════════════════════════════════════════════════╝");
    console.log("");

}); // end Java.perform
