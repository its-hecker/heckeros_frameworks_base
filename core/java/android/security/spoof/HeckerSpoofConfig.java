/* SPDX-License-Identifier: Apache-2.0 */
package android.security.spoof;

import android.app.ActivityManager;
import android.os.RemoteException;

/** Private framework API used by native Settings. @hide */
public final class HeckerSpoofConfig {
    public static final int GAMES = 1;
    public static final int TARGETS = 2;
    public static final int KEYBOX = 3;
    public static final int PATCH = 4;
    public static final int MAX_BYTES = 256 * 1024;

    private HeckerSpoofConfig() {}

    public static String get(int kind) {
        try {
            return ActivityManager.getService().getHeckerSpoofConfig(kind);
        } catch (RemoteException error) {
            throw error.rethrowFromSystemServer();
        }
    }

    public static void put(int kind, String value) {
        try {
            ActivityManager.getService().setHeckerSpoofConfig(kind, value);
        } catch (RemoteException error) {
            throw error.rethrowFromSystemServer();
        }
    }
}
