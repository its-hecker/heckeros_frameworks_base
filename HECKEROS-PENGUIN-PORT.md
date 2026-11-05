# PenguinOS integrity integration — experimental Coral source

**Status (2026-11-05): NOT BUILD-VALIDATED. NOT SELECTED BY THE CORAL MANIFEST.**

This branch starts at HeckerOS frameworks/base `4af276bc5ceea071ef0da5ea440cda4470c08df6`
and incorporates selected source from `Project-PenguinOS/frameworks_base` at
`947644f88d63b82179deec4d9149a1e4332584a3` (`celerity`, Android 17).

## Applied in this isolated branch

- TrickyStore service: atomically publish target and patch configuration; preserve
  last valid configuration when private ActivityManager transport fails; accept
  explicit empty policy as a clear.
- GameProps service: consolidate game profiles and optional per-app device
  profiles; pass the app context before loading application code.
- Remove `PropImitationHooks.java` and its Instrumentation paths; move Photos
  property/feature handling into the Hecker PIF service, keep app scope isolated,
  and enforce task permissions unconditionally.
- No keyboxes or certificates are bundled. Existing Hecker system-UID/private
  keybox and configured PIF APIs must not be exposed to unprivileged apps.

## Remaining before this may be selected by a ROM build

1. **Play Integrity integration**: PenguinOS PIF uses private
   `IActivityManager` settings transport and does not provide all HeckerOS
   `loadConfig(String)`, `spoofProvider()` and
   `shouldBlockCertificateChain()` hooks. Adapt the actual service to
   HeckerOS's existing privileged Settings storage and per-process controls.
   Do not replace the file wholesale without reconciling the caller APIs.
2. **ROM visibility**: PenguinOS updates `AppsFilterBase` and
   `ComputerEngine`. They overlap Hecker's own
   `HeckerRootVisibility` per-user privacy and Bionic filtering. Merge the
   package visibility rules with trusted-system/default-launcher allowances;
   then remove the old `hecker_hide_custom_rom_apps` UI and setting only once
   its read/write paths have been migrated.
3. **Settings UI**: replace the redundant Spoofing hub with one consistent
   integrity entry point; preserve import/export, explicit disable/clear,
   per-app targets, private keystore UID checks and user configuration.
4. **Dependencies**: update the pinned source revision and platform-feature
   checks *together* with matching Settings and suite changes. Run source
   adapters with their guarded revert/apply flow. No force reset of dirty ROM
   worktrees.
5. **Validation**: compile full frameworks/base, Settings and ROM using the
   pinned Android 17 source; run Java/AIDL/resources/Soong/SELinux checks;
   test Coral boot, actual attestation results, GMS/Play Store/Photos,
   root-manager privacy, app visibility, profile persistence and recovery
   from failed Binder reads. No host-only check establishes a Play Integrity
   verdict or a working STRONG verdict.

The stable `fix/device-feedback-20261105` Coral manifest continues to pin the
previous compiled-source baseline while this migration is reviewed.
