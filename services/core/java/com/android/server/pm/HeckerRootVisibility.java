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
            "com.topjohnwu.magisk",
            "com.rifsxd.ksunext",
            "io.github.lsposed.manager",
            "io.github.vvb2060.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "me.weishu.kernelsu",
            "me.bmax.apatch",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.chelpus.luckypatcher",
            "com.solohsu.android.edxp.manager",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager",
            "cc.madkite.freedom",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.zachspong.temprootremovejb"
    );

    private static final Set<String> ROM_PACKAGES_EXACT = Set.of(
            "lineageos.platform", "org.hecker.suite", "org.hecker.netlab", "org.hecker.vpn", "org.hecker.librepods"
    );

    private static final String[] ROM_PACKAGE_PREFIXES = {
            "org.lineageos.",
            "co.aospa.",
            "org.protonaosp.",
            "org.omnirom.",
            "com.android.axion.",
            "com.axion.",
            "com.libremobileos.",
            "com.crdroid.",
            "io.chaldeaprjkt.",
            "org.lunaris."
    };

    private static final Set<String> ROM_PROTECTED = Set.of("android", "com.android.systemui",
            "com.android.settings", "com.android.permissioncontroller", "org.hecker.suite",
            "com.android.launcher3", "com.google.android.apps.nexuslauncher", "org.hecker.vpn", "org.hecker.netlab", "org.hecker.librepods");
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
        if (packageName == null) return 0;
        Map<String, Integer> selected = sCompatibility.get(userId);
        int flags = selected == null ? 0 : selected.getOrDefault(packageName, 0);
        // ROM visibility is the device-wide default for app processes.
        // Native OS/Hecker components retain their real feature properties and service access.
        return ROM_PROTECTED.contains(packageName) ? flags & ~16 : flags | 16;
    }

    /** APK code is shared: every installed Android user must explicitly opt in. */
    static boolean allowDowngrade(String packageName, int[] installedUsers) {
        if (installedUsers == null || installedUsers.length == 0) return false;
        for (int userId : installedUsers) {
            if ((getCompatibilityFlags(packageName, userId) & 2) == 0) return false;
        }
        return true;
    }

    static boolean isRomPackage(String packageName) {
        if (packageName == null) return false;
        if (ROM_PACKAGES_EXACT.contains(packageName)) return true;
        for (String prefix : ROM_PACKAGE_PREFIXES) if (packageName.startsWith(prefix)) return true;
        return false;
    }

    static boolean shouldHide(int callingUid, Object callingSetting, PackageStateInternal target) {
        int appId = UserHandle.getAppId(callingUid);
        if (appId < Process.FIRST_APPLICATION_UID || target == null
                || appId == target.getAppId())
            return false;
        boolean manager = MANAGERS.contains(target.getPackageName());
        boolean romComponent = isRomPackage(target.getPackageName());
        if (!manager && !romComponent) return false;
        Set<String> selected = sTargets.get(UserHandle.getUserId(callingUid));
        if (callingSetting instanceof PackageStateInternal) {
            String name = ((PackageStateInternal) callingSetting).getPackageName();
            return manager && selected != null && selected.contains(name)
                    || romComponent && (getCompatibilityFlags(name, UserHandle.getUserId(callingUid)) & 16) != 0;
        }
        if (callingSetting instanceof SharedUserApi) {
            for (PackageStateInternal pkg : ((SharedUserApi) callingSetting).getPackageStates()) {
                if (manager && selected != null && selected.contains(pkg.getPackageName())
                        || romComponent && (getCompatibilityFlags(pkg.getPackageName(),
                                UserHandle.getUserId(callingUid)) & 16) != 0) return true;
            }
        }
        return false;
    }
}
