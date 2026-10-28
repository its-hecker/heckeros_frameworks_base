/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.display.mode;

/**
 * Holds a low refresh-rate blocking zone until brightness clears its exit margin.
 *
 * <p>Thresholds use the same normalized brightness and paired lux values as
 * {@link DisplayModeDirector}. Negative thresholds retain their native meaning.
 * This class selects no refresh rate and writes no settings. Callers serialize
 * access with the display-mode director lock and reset it when policy changes.
 */
final class LowZoneBrightnessHysteresis {
    private final float mBrightnessExitDelta;
    private boolean mInside;

    LowZoneBrightnessHysteresis(float brightnessExitDelta) {
        mBrightnessExitDelta = Float.isFinite(brightnessExitDelta)
                ? Math.max(0f, Math.min(1f, brightnessExitDelta)) : 0f;
    }

    boolean update(float brightness, float lux, float[] displayThresholds, float[] luxThresholds) {
        if (!Float.isFinite(brightness) || brightness < 0f
                || displayThresholds == null || luxThresholds == null
                || displayThresholds.length != luxThresholds.length) {
            reset();
            return false;
        }

        final float exitDelta = mInside ? mBrightnessExitDelta : 0f;
        boolean inside = false;
        for (int i = 0; i < displayThresholds.length; i++) {
            final float display = displayThresholds[i];
            final float ambient = luxThresholds[i];
            final float displayLimit = Math.min(1f, display + exitDelta);
            if (display >= 0f && ambient >= 0f) {
                inside = brightness <= displayLimit && lux <= ambient;
            } else if (display >= 0f) {
                inside = brightness <= displayLimit;
            } else if (ambient >= 0f) {
                inside = lux <= ambient;
            }
            if (inside) {
                break;
            }
        }
        mInside = inside;
        return inside;
    }

    void reset() {
        mInside = false;
    }
}
