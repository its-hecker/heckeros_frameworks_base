/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.pm;

import android.content.Context;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Binder;
import android.os.Handler;
import android.os.Process;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;
import com.android.server.FgThread;
import com.android.server.pm.pkg.PackageStateInternal;
import com.android.server.pm.pkg.SharedUserApi;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Per-user opt-in privacy. Query paths do no I/O or PackageManager Binder calls. */
public final class HeckerRootVisibility {
    static final String SETTING = "hecker_root_private_apps";
    private static final Set<String> MANAGERS = Set.of(
            "com.rifsxd.ksunext", "me.weishu.kernelsu", "com.topjohnwu.magisk", "me.bmax.apatch");
    private static volatile Map<Integer, Set<String>> sTargets = Collections.emptyMap();
    private static volatile Map<Integer, Map<String, Integer>> sCompatibility = Collections.emptyMap();
    static final String[] SETTINGS = {SETTING, "hecker_allow_downgrade_apps",
            "hecker_hide_developer_options_apps", "hecker_bootloader_spoof_apps"};
    private static boolean sStarted;

    static synchronized void start(Context context) {
        if (sStarted || context == null || !SystemProperties.getBoolean(
                "ro.hecker.coral_root_privacy", false)) return;
        sStarted = true;
        Handler handler = FgThread.getHandler();
        handler.post(() -> {
            for (String setting : SETTINGS) {
                context.getContentResolver().registerContentObserver(Settings.Secure.getUriFor(setting),
                        false, new ContentObserver(handler) {
                            @Override public void onChange(boolean selfChange, Uri uri, int userId) {
                                refresh(context);
                            }
                        }, UserHandle.USER_ALL);
            }
            refresh(context);
        });
    }

    private static void refresh(Context context) {
        long identity = Binder.clearCallingIdentity();
        try {
            Map<Integer, Set<String>> next = new HashMap<>();
            Map<Integer, Map<String, Integer>> compatibility = new HashMap<>();
            for (UserHandle user : context.getSystemService(UserManager.class).getUserHandles(true)) {
                Map<String, Integer> flags = new HashMap<>();
                Set<String> privateApps = new HashSet<>();
                for (int option = 0; option < SETTINGS.length; option++) {
                    String value = Settings.Secure.getStringForUser(context.getContentResolver(),
                            SETTINGS[option], user.getIdentifier());
                    if (value == null || value.length() > 65536) continue;
                    for (String name : value.split(":")) {
                        if (!name.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))
                            continue;
                        flags.merge(name, 1 << option, (a, b) -> a | b);
                        if (option == 0) privateApps.add(name);
                    }
                }
                next.put(user.getIdentifier(), Collections.unmodifiableSet(privateApps));
                compatibility.put(user.getIdentifier(), Collections.unmodifiableMap(flags));
            }
            sCompatibility = Collections.unmodifiableMap(compatibility);
            sTargets = Collections.unmodifiableMap(next);
        } catch (RuntimeException unavailable) {
            // Retain the last complete snapshot if a user/provider is temporarily unavailable.
            android.util.Slog.w("HeckerRootVisibility", "Could not refresh package privacy");
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    /** Read-only hot path: no settings/provider/Binder operations. */
    public static int getCompatibilityFlags(String packageName, int userId) {
        Map<String, Integer> selected = sCompatibility.get(userId);
        return selected == null ? 0 : selected.getOrDefault(packageName, 0);
    }

    /** APK code is shared: every installed Android user must explicitly opt in. */
    static boolean allowDowngrade(String packageName, int[] installedUsers) {
        if (installedUsers == null || installedUsers.length == 0) return false;
        for (int userId : installedUsers) {
            if ((getCompatibilityFlags(packageName, userId) & 2) == 0) return false;
        }
        return true;
    }

    static boolean shouldHide(int callingUid, Object callingSetting, PackageStateInternal target) {
        int appId = UserHandle.getAppId(callingUid);
        if (appId < Process.FIRST_APPLICATION_UID || target == null
                || appId == target.getAppId() || !MANAGERS.contains(target.getPackageName()))
            return false;
        Set<String> selected = sTargets.get(UserHandle.getUserId(callingUid));
        if (selected == null || selected.isEmpty()) return false;
        if (callingSetting instanceof PackageStateInternal) {
            return selected.contains(((PackageStateInternal) callingSetting).getPackageName());
        }
        if (callingSetting instanceof SharedUserApi) {
            for (PackageStateInternal pkg : ((SharedUserApi) callingSetting).getPackageStates()) {
                if (selected.contains(pkg.getPackageName())) return true;
            }
        }
        return false;
    }
}
