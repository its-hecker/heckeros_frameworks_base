/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.spoof;

import android.content.Context;
import android.os.Binder;
import android.os.Environment;
import android.os.FileUtils;
import android.os.Process;
import android.os.UserHandle;
import android.security.spoof.HeckerSpoofConfig;
import android.security.trickystore.KeyBoxManager;
import android.util.AtomicFile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** System-only storage; private key material never enters SettingsProvider or logs. */
public final class HeckerSpoofConfigStore {
    private static final Set<String> GAME_FIELDS = Set.of(
            "BRAND", "MANUFACTURER", "MODEL", "DEVICE", "PRODUCT", "BOARD", "HARDWARE",
            "FINGERPRINT", "ID", "DISPLAY", "TYPE", "TAGS", "BOOTLOADER", "INCREMENTAL", "RELEASE");
    private final Context mContext;
    private final Map<Integer, String> mValues = new LinkedHashMap<>();
    private boolean mLoaded;

    public HeckerSpoofConfigStore(Context context) { mContext = context; }

    private static void checkKind(int kind) {
        if (kind < HeckerSpoofConfig.GAMES || kind > HeckerSpoofConfig.PATCH) {
            throw new IllegalArgumentException("Unknown compatibility configuration");
        }
    }

    private static void enforceManager() {
        int uid = Binder.getCallingUid();
        if (uid != Process.SYSTEM_UID && uid != Process.ROOT_UID) {
            throw new SecurityException("Only primary system Settings may manage compatibility profiles");
        }
    }

    private static AtomicFile file(int kind) {
        checkKind(kind);
        return new AtomicFile(new File(Environment.getDataSystemDirectory(),
                "hecker_spoof_" + kind));
    }

    private void load() {
        if (mLoaded) return;
        for (int kind = HeckerSpoofConfig.GAMES; kind <= HeckerSpoofConfig.PATCH; kind++) {
            try {
                AtomicFile source = file(kind);
                if (!source.getBaseFile().exists()) continue;
                try (java.io.FileInputStream stream = source.openRead()) {
                    byte[] bytes = stream.readNBytes(HeckerSpoofConfig.MAX_BYTES + 1);
                    if (bytes.length <= HeckerSpoofConfig.MAX_BYTES) {
                        mValues.put(kind, validate(kind, new String(bytes, StandardCharsets.UTF_8)));
                    }
                }
            } catch (Exception ignored) {
                // An absent or invalid stored profile is inert. Never log its contents.
            }
        }
        mLoaded = true;
    }

    public synchronized String getForSettings(int kind) {
        enforceManager();
        checkKind(kind);
        load();
        return mValues.get(kind);
    }

    public synchronized void put(int kind, String value) {
        enforceManager();
        checkKind(kind);
        load();
        String normalized = value == null || value.trim().isEmpty() ? null : validate(kind, value);
        AtomicFile target = file(kind);
        FileOutputStream output = null;
        long identity = Binder.clearCallingIdentity();
        try {
            // Persist an empty file for a reversible disable; AtomicFile can roll back failures.
            output = target.startWrite();
            if (FileUtils.setPermissions(output.getFD(), 0600, -1, -1) != 0) {
                throw new java.io.IOException("Cannot protect compatibility configuration");
            }
            output.write((normalized == null ? "" : normalized).getBytes(StandardCharsets.UTF_8));
            target.finishWrite(output);
            if (normalized == null) mValues.remove(kind); else mValues.put(kind, normalized);
        } catch (java.io.IOException error) {
            target.failWrite(output);
            throw new IllegalStateException("Unable to save compatibility configuration");
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    public synchronized String getForCaller(int kind) {
        checkKind(kind);
        load();
        int uid = Binder.getCallingUid();
        if (UserHandle.getUserId(uid) != UserHandle.USER_SYSTEM
                || UserHandle.getAppId(uid) < Process.FIRST_APPLICATION_UID) return null;
        String[] packages = mContext.getPackageManager().getPackagesForUid(uid);
        if (packages == null) return null;
        try {
            if (kind == HeckerSpoofConfig.GAMES) {
                String value = mValues.get(kind);
                if (value == null) return null;
                JSONObject config = new JSONObject(value);
                JSONObject games = config.getJSONObject("games");
                JSONObject ownGames = new JSONObject();
                for (String name : packages) if (games.has(name)) ownGames.put(name, games.get(name));
                if (ownGames.length() == 0) return null;
                config.put("games", ownGames);
                return config.toString();
            }
            Map<String, String> targets = targets(mValues.get(HeckerSpoofConfig.TARGETS));
            JSONArray ownTargets = new JSONArray();
            for (String name : packages) if (targets.containsKey(name)) {
                ownTargets.put(new JSONObject().put("package", name).put("mode", targets.get(name)));
            }
            if (ownTargets.length() == 0) return null;
            return kind == HeckerSpoofConfig.TARGETS ? ownTargets.toString() : mValues.get(kind);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean packageName(String name) {
        return name != null && name.length() <= 255
                && name.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+");
    }

    static Map<String, String> targets(String value) throws Exception {
        Map<String, String> result = new LinkedHashMap<>();
        if (value == null || value.trim().isEmpty()) return result;
        if (value.trim().startsWith("[")) {
            JSONArray list = new JSONArray(value);
            for (int i = 0; i < list.length(); i++) {
                JSONObject item = list.getJSONObject(i);
                result.put(item.getString("package"), item.optString("mode", "AUTO").toUpperCase(Locale.ROOT));
            }
        } else {
            for (String line : value.split("\\R")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String mode = line.endsWith("!") ? "GENERATE" : line.endsWith("?") ? "LEAF_HACK" : "AUTO";
                String name = mode.equals("AUTO") ? line : line.substring(0, line.length() - 1).trim();
                result.put(name, mode);
            }
        }
        if (result.size() > 512) throw new IllegalArgumentException();
        for (Map.Entry<String, String> item : result.entrySet()) {
            if (!packageName(item.getKey()) || !Set.of("AUTO", "GENERATE", "LEAF_HACK").contains(item.getValue())) {
                throw new IllegalArgumentException();
            }
        }
        return result;
    }

    static String validate(int kind, String value) {
        try {
            if (value.getBytes(StandardCharsets.UTF_8).length > HeckerSpoofConfig.MAX_BYTES) {
                throw new IllegalArgumentException();
            }
            switch (kind) {
                case HeckerSpoofConfig.GAMES: {
                    JSONObject input = new JSONObject(value);
                    JSONObject games = input.getJSONObject("games");
                    if (games.length() > 512) throw new IllegalArgumentException();
                    Iterator<String> names = games.keys();
                    while (names.hasNext()) {
                        String name = names.next();
                        if (!packageName(name)) throw new IllegalArgumentException();
                        JSONObject props = games.getJSONObject(name);
                        Iterator<String> fields = props.keys();
                        while (fields.hasNext()) {
                            String field = fields.next();
                            Object content = props.get(field);
                            if (!GAME_FIELDS.contains(field) || !(content instanceof String)
                                    || ((String) content).length() > 512) throw new IllegalArgumentException();
                        }
                    }
                    return new JSONObject().put("enabled", input.optBoolean("enabled", true))
                            .put("debug", false).put("games", games).toString();
                }
                case HeckerSpoofConfig.TARGETS: {
                    JSONArray list = new JSONArray();
                    for (Map.Entry<String, String> entry : targets(value).entrySet()) {
                        list.put(new JSONObject().put("package", entry.getKey()).put("mode", entry.getValue()));
                    }
                    return list.toString();
                }
                case HeckerSpoofConfig.KEYBOX: {
                    String xml = value.trim();
                    if (!xml.startsWith("<")) xml = new String(Base64.getDecoder().decode(xml), StandardCharsets.UTF_8).trim();
                    String upper = xml.toUpperCase(Locale.ROOT);
                    if (!xml.startsWith("<") || upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY")) {
                        throw new IllegalArgumentException();
                    }
                    KeyBoxManager manager = new KeyBoxManager();
                    manager.parseKeybox(xml);
                    if (!manager.hasKeyboxes()) throw new IllegalArgumentException();
                    return xml;
                }
                case HeckerSpoofConfig.PATCH: {
                    JSONObject patch = new JSONObject();
                    if (value.trim().startsWith("{")) patch = new JSONObject(value);
                    else {
                        for (String line : value.split("\\R")) {
                            line = line.trim();
                            if (line.isEmpty() || line.startsWith("#")) continue;
                            int equals = line.indexOf('=');
                            if (equals < 0) patch.put("all", line);
                            else patch.put(line.substring(0, equals).trim(), line.substring(equals + 1).trim());
                        }
                    }
                    if (patch.length() == 0) throw new IllegalArgumentException();
                    Iterator<String> keys = patch.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        if (!Set.of("system", "vendor", "boot", "all").contains(key)) throw new IllegalArgumentException();
                        String date = patch.getString(key).replace("-", "");
                        if (!date.matches("[0-9]{8}")) throw new IllegalArgumentException();
                        java.time.LocalDate.parse(date, java.time.format.DateTimeFormatter.BASIC_ISO_DATE);
                        patch.put(key, date);
                    }
                    return patch.toString();
                }
                default: throw new IllegalArgumentException();
            }
        } catch (Exception ignored) {
            throw new IllegalArgumentException("Invalid compatibility configuration (type " + kind + ")");
        }
    }
}
