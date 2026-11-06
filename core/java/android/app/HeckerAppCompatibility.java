/* SPDX-License-Identifier: Apache-2.0 */
package android.app;

import android.os.Process;
import android.os.Build;
import android.util.Log;

/**
 * Process-local compatibility policy delivered by PackageManager.
 * @hide
 */
public final class HeckerAppCompatibility {
    public static final int ROOT_MANAGER_PRIVACY = 1;
    public static final int ALLOW_DOWNGRADE = 2;
    public static final int HIDE_DEVELOPER_OPTIONS = 4;
    public static final int SPOOF_BOOTLOADER = 8;
    public static final int HIDE_CUSTOM_ROM = 16;
    public static final int ALL_FLAGS = 31;
    private static volatile int sFlags;
    private static volatile int sUserId = -1;
    private static boolean sBootPropertiesApplied;
    private static final String REAL_BUILD_TYPE = Build.TYPE;
    private static final String REAL_BUILD_TAGS = Build.TAGS;
    private static boolean sBuildFieldsCustomized;

    private HeckerAppCompatibility() {}

    /** Called before app code, including package-specific app-zygote preload. */
    public static void initialize(int flags, int uid) {
        // Never alter the system server, global zygote, root or shell processes.
        if (uid < 0 || uid % 100000 < Process.FIRST_APPLICATION_UID) {
            sFlags = 0;
            sUserId = -1;
            return;
        }
        sUserId = uid / 100000;
        sFlags = flags & ALL_FLAGS;
        boolean hideRom = (sFlags & HIDE_CUSTOM_ROM) != 0;
        if (hideRom != sBuildFieldsCustomized) {
            try {
                // Build was initialized in zygote before the native per-app policy existed.
                // Match the two software build fields without replacing device identity or SDK.
                java.lang.reflect.Field type = Build.class.getDeclaredField("TYPE");
                java.lang.reflect.Field tags = Build.class.getDeclaredField("TAGS");
                type.setAccessible(true); tags.setAccessible(true);
                type.set(null, hideRom ? "user" : REAL_BUILD_TYPE);
                tags.set(null, hideRom ? "release-keys" : REAL_BUILD_TAGS);
                sBuildFieldsCustomized = hideRom;
            } catch (ReflectiveOperationException | RuntimeException unavailable) {
                Log.w("HeckerAppCompatibility", "Software build fields unavailable", unavailable);
            }
        }
        try {
            // Also clear an app-zygote child's inherited native flag when its profile is off.
            if (!nativeConfigureRomHide(hideRom) && hideRom) Log.w("HeckerAppCompatibility",
                    "Native ROM compatibility is unavailable in this image");
        } catch (LinkageError | RuntimeException unavailable) {
            if (hideRom) Log.w("HeckerAppCompatibility", "ROM compatibility unavailable", unavailable);
        }
        try {
            nativeConfigureAppPrivacy(sFlags);
        } catch (LinkageError | RuntimeException unavailable) {
            if ((sFlags & HIDE_DEVELOPER_OPTIONS) != 0)
                Log.w("HeckerAppCompatibility", "Native debugging privacy unavailable", unavailable);
        }
        // A child of an app zygote inherits its already-private property mappings.
        if ((sFlags & SPOOF_BOOTLOADER) != 0 && !sBootPropertiesApplied) {
            try {
                sBootPropertiesApplied = nativeApplyBootProperties();
                if (!sBootPropertiesApplied) Log.w("HeckerAppCompatibility",
                        "Could not apply process-local boot properties");
            } catch (LinkageError | RuntimeException unavailable) {
                Log.w("HeckerAppCompatibility", "Boot property compatibility unavailable",
                        unavailable);
            }
        }
    }

    /** The current app opted into boot-state compatibility; core UIDs are excluded at bind. */
    public static boolean isBootloaderCompatibilityEnabled() {
        return (sFlags & SPOOF_BOOTLOADER) != 0 && sUserId >= 0;
    }

    /** Runs before Settings' value cache; never writes a real setting. */
    public static String settingOverride(String table, String name, int queryUserId) {
        if ((sFlags & HIDE_DEVELOPER_OPTIONS) == 0 || queryUserId != sUserId) return null;
        if (!("global".equals(table) || "secure".equals(table))) return null;
        return "development_settings_enabled".equals(name) || "adb_enabled".equals(name)
                || "adb_wifi_enabled".equals(name) ? "0" : null;
    }

    private static native boolean nativeConfigureAppPrivacy(int flags);
    private static native boolean nativeApplyBootProperties();
    private static native boolean nativeConfigureRomHide(boolean enabled);
}
