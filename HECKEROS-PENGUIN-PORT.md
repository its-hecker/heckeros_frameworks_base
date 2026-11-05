# PenguinOS integrity integration — Coral

Source integration is complete. Full Android/Soong compilation and Coral phone
validation remain required; host checks do not establish a Play Integrity verdict.

Upstream: Project-PenguinOS/frameworks_base at
947644f88d63b82179deec4d9149a1e4332584a3 (celerity, Android 17).
Hecker baseline: 4af276bc5ceea071ef0da5ea440cda4470c08df6.

## Integrated behavior

- Merge Penguin PIF parsing, initial-API precedence, retry handling and Photos
  feature/profile catalogs with the existing Hecker configuration store. Retain
  explicit disable, numeric Play Store options, process scope and the existing
  JNI/keystore interfaces. Context initialization works before Application exists.
- Preserve independent Photos configuration and its default through upgrades.
  Failed settings reads can retry; successful empty/disabled settings stay off.
- Import the consolidated GameProps service. Publish JSON profiles after complete
  parsing, reject malformed replacements without partial rules, and retain JSON
  priority over named per-app profiles.
- Import TrickyStore atomic target/patch snapshots and transport-failure handling.
  Include the required strict patch-date validator, clear cached configuration
  across process UID changes, and retain the existing private importer/signer.
- Merge Penguin ROM/root package catalogs and direct intent-resolution filtering.
  Preserve trusted system/privileged callers, shared-UID allowances, the current
  default Home in each user and self access. Root-manager privacy remains an
  independent per-app selection. ROM visibility is the existing device-wide
  default; the obsolete per-app ROM setting is no longer read or observed.
- Remove PropImitationHooks and its callers. Task permission checks are
  unconditional. No Obscura implementation exists in this selected framework.
- Settings uses one Play Integrity page, with the old private hub component as an
  upgrade redirect. Preserve saved configuration and private key access boundaries;
  add non-secret profile/target exports and an independent Photos switch.

No keyboxes or private certificates are bundled. Key material remains in Hecker's
system-only store; app processes receive only the permitted UID-scoped data.

## Validation and builds

Run Suite's check_spoofing.py, check_spoofing_hub.py,
check_platform_features.py, check_app_compatibility.py and
check_native_ports.py, plus the host suite and Coral integration checks.
These exercise Android 17 Java/resources, private Binder contracts, real parsers,
synthetic RSA/EC chains, lifecycle retry, package visibility and native adapters.

The matching Suite and Coral local manifest must select these framework sources
and the matching Settings revision together. On an already prepared ServerHive
checkout, run the old Suite's guarded prepare.py --revert BEFORE changing
its manifest and syncing; then use the existing default-jobs RBE build helper.
Never force-reset or force-sync unfamiliar local edits.

After building, test boot, Settings imports/exports and recreation, PIF/Photos
switches with app restarts, actual attestation results, GMS/Play Store/Photos,
root-manager privacy, default launchers and secondary-user package visibility.
