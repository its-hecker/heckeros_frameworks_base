/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.pm;

import android.content.ContentResolver;
import android.content.pm.SigningDetails;
import android.os.Process;
import android.util.Slog;

import org.json.JSONException;
import org.json.JSONObject;

import com.android.internal.pm.parsing.pkg.ParsedPackage;
import com.android.internal.pm.pkg.parsing.ParsingPackageUtils;

/**
 * Explicit per-app test compatibility. Only the named user-installed package
 * may bypass the installed-data certificate comparison. APKs must still carry
 * valid cryptographic signatures; system and shared-UID apps remain protected.
 */
final class HeckerSignatureTestPolicy {
    private static final String KEY = "hecker_signature_allowed_packages";
    private HeckerSignatureTestPolicy() {}

    /**
     * Permit a selected user app to redeclare permissions and permission groups
     * that it ALREADY owns when installing a differently signed update.
     *
     * This is only the installer ownership check, not permission grants:
     * permissions belonging to any other package remain protected, including
     * platform permissions. All other checks from allowMismatch still apply.
     */
    static boolean allowOwnPermissionRedeclaration(PackageSetting previousPackage,
            SharedUserSetting sharedUser, ParsedPackage incoming,
            String existingOwner, int scanFlags, int parseFlags,
            ContentResolver resolver) {
        return incoming != null && existingOwner != null
                && existingOwner.equals(incoming.getPackageName())
                && allowMismatch(previousPackage, sharedUser, null, incoming,
                        scanFlags, parseFlags, resolver);
    }

    static boolean allowMismatch(PackageSetting previousPackage,
            SharedUserSetting sharedUser, PackageSetting disabledSystemPackage,
            ParsedPackage incoming, int scanFlags, int parseFlags,
            ContentResolver resolver) {
        if (resolver == null || previousPackage == null || incoming == null) return false;
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
            final String value = android.provider.Settings.Global.getString(resolver, KEY);
            if (value == null || value.isEmpty()
                    || !new JSONObject(value).optBoolean(incoming.getPackageName(), false)) {
                return false;
            }
        } catch (JSONException | RuntimeException unavailable) {
            return false; // Invalid selection list or Settings provider: fail closed.
        }
        Slog.w("HeckerSignatureTest", "Allowing test signature-mismatch update of "
                + incoming.getPackageName());
        return true;
    }
}
