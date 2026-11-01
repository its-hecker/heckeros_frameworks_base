/* SPDX-License-Identifier: Apache-2.0 */
package android.app;

import android.os.Process;
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
    public static final int ALL_FLAGS = 15;
    private static volatile int sFlags;
    private static volatile int sUserId = -1;
    private static boolean sBootPropertiesApplied;

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

    /** Runs before Settings' value cache; never writes a real setting. */
    public static String settingOverride(String table, String name, int queryUserId) {
        if ((sFlags & HIDE_DEVELOPER_OPTIONS) == 0 || queryUserId != sUserId) return null;
        if (!("global".equals(table) || "secure".equals(table))) return null;
        return "development_settings_enabled".equals(name) || "adb_enabled".equals(name)
                || "adb_wifi_enabled".equals(name) ? "0" : null;
    }

    private static native boolean nativeApplyBootProperties();
}
