/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.pm;

import android.content.ContentResolver;
import android.content.pm.SigningDetails;
import android.os.Build;
import android.os.Process;
import android.util.Slog;

import com.android.internal.pm.parsing.pkg.ParsedPackage;
import com.android.internal.pm.pkg.parsing.ParsingPackageUtils;

/**
 * Temporary owner-controlled package update compatibility for userdebug builds.
 * This only skips the installed-data certificate compatibility check for
 * ordinary user packages; all APKs must still be cryptographically valid.
 */
final class HeckerSignatureTestPolicy {
    private static final String KEY = "hecker_package_signature_test_mode";
    private HeckerSignatureTestPolicy() {}

    static boolean allowMismatch(PackageSetting previousPackage,
            SharedUserSetting sharedUser, PackageSetting disabledSystemPackage,
            ParsedPackage incoming, int scanFlags, int parseFlags,
            ContentResolver resolver) {
        if (!Build.IS_DEBUGGABLE || resolver == null
                || previousPackage == null || incoming == null) return false;
        // Never weaken system, preloaded, shared-UID, APEX or library trust.
        if (previousPackage.isSystem() || previousPackage.isUpdatedSystemApp()
                || previousPackage.getAppId() < Process.FIRST_APPLICATION_UID
                || sharedUser != null || disabledSystemPackage != null
                || previousPackage.getPkg() == null
                || previousPackage.getPkg().isStaticSharedLibrary()
                || previousPackage.getPkg().isSdkLibrary()
                || incoming.isStaticSharedLibrary() || incoming.isSdkLibrary()
                || incoming.isCoreApp()
                || !previousPackage.getPackageName().equals(incoming.getPackageName())
                || (scanFlags & (PackageManagerService.SCAN_BOOTING
                        | PackageManagerService.SCAN_AS_APEX
                        | PackageManagerService.SCAN_AS_SYSTEM)) != 0
                || (parseFlags & ParsingPackageUtils.PARSE_IS_SYSTEM_DIR) != 0) {
            return false;
        }
        final SigningDetails oldSigners = previousPackage.getSigningDetails();
        final SigningDetails newSigners = incoming.getSigningDetails();
        if (oldSigners == null || newSigners == null
                || oldSigners == SigningDetails.UNKNOWN
                || newSigners == SigningDetails.UNKNOWN
                || oldSigners.getSignatures() == null || newSigners.getSignatures() == null) {
            return false;
        }
        // Do not alter normal certificate rotation and rollback behavior.
        if (newSigners.checkCapability(oldSigners,
                    SigningDetails.CertCapabilities.INSTALLED_DATA)
                || oldSigners.checkCapability(newSigners,
                    SigningDetails.CertCapabilities.ROLLBACK)) return false;
        try {
            if (android.provider.Settings.Global.getInt(resolver, KEY, 0) != 1) return false;
        } catch (RuntimeException unavailable) {
            return false; // Settings provider unavailable: fail closed.
        }
        Slog.w("HeckerSignatureTest", "Allowing test signature-mismatch update of "
                + incoming.getPackageName());
        return true;
    }
}
