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
final class HeckerRootVisibility {
    static final String SETTING = "hecker_root_private_apps";
    private static final Set<String> MANAGERS = Set.of(
            "com.rifsxd.ksunext", "me.weishu.kernelsu", "com.topjohnwu.magisk", "me.bmax.apatch");
    private static volatile Map<Integer, Set<String>> sTargets = Collections.emptyMap();
    private static boolean sStarted;

    static synchronized void start(Context context) {
        if (sStarted || context == null || !SystemProperties.getBoolean(
                "ro.hecker.coral_root_privacy", false)) return;
        sStarted = true;
        Handler handler = FgThread.getHandler();
        handler.post(() -> {
            context.getContentResolver().registerContentObserver(Settings.Secure.getUriFor(SETTING),
                    false, new ContentObserver(handler) {
                        @Override public void onChange(boolean selfChange, Uri uri, int userId) {
                            refresh(context);
                        }
                    }, UserHandle.USER_ALL);
            refresh(context);
        });
    }

    private static void refresh(Context context) {
        long identity = Binder.clearCallingIdentity();
        try {
            Map<Integer, Set<String>> next = new HashMap<>();
            for (UserHandle user : context.getSystemService(UserManager.class).getUserHandles(true)) {
                Set<String> names = new HashSet<>();
                String value = Settings.Secure.getStringForUser(context.getContentResolver(),
                        SETTING, user.getIdentifier());
                if (value != null && value.length() <= 65536) {
                    for (String name : value.split(":")) {
                        if (name.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))
                            names.add(name);
                    }
                }
                next.put(user.getIdentifier(), Collections.unmodifiableSet(names));
            }
            sTargets = Collections.unmodifiableMap(next);
        } catch (RuntimeException unavailable) {
            // Retain the last complete snapshot if a user/provider is temporarily unavailable.
            android.util.Slog.w("HeckerRootVisibility", "Could not refresh package privacy");
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
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
