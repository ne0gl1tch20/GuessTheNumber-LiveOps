# GuessTheNumber LiveOps

This repository publishes signed Lua activity bundles for the Android app [GuessTheNumber](https://github.com/ne0gl1tch20/GuessTheNumber). The app downloads the manifest over HTTPS and verifies its RSA signature and each script hash before activating a bundle. The same signed payload can carry the declarative seasonal event catalog; Kotlin validates event eligibility and grants all rewards.

## Publish a change

1. Edit `liveops-config.json` and the referenced files in `scripts/`. The optional `events` array publishes seasonal offers through the same signed payload; update `eventManifestVersion` when its schema changes.
2. **Increase `bundleVersion` for every changed publication.** The currently configured version is `3`. Do not reuse a version for different content and do not lower the number to roll back.
3. Open a pull request and merge it to `main`.
4. Confirm the [Publish LiveOps workflow](.github/workflows/publish-liveops.yml) completes successfully.
5. In the app's Lua Activity Hub, refresh the signed LiveOps bundle and test the activity.

The app treats a refresh of the already-active version as “already up to date”. The publisher also verifies the previous signed manifest and rejects changed payload bytes unless the new bundle version is strictly higher. The app keeps a separate highest-accepted-version marker, so switching to a previously verified cached bundle for recovery does not lower anti-rollback protection. To restore previous script content, publish that content with a new, higher version.

Pull requests run the **Validate LiveOps content** workflow. It checks the config and script files and tests duplicate IDs, duplicate filenames, unsafe paths, empty scripts and bundle-version progression. The app repository has a separate workflow for Android unit tests and lint. Event definitions are validated for unique IDs, allowed status values, timezone-aware dates, bounded rewards and progression requirements before signing. Offline, interrupted-download and cache-tampering checks are documented in the app's [LiveOps reliability test plan](https://github.com/ne0gl1tch20/GuessTheNumber/blob/master/docs/LIVEOPS_RELIABILITY_TEST_PLAN.md).

## Lua activity contract

Every script listed in `liveops-config.json` must return a Lua table matching the host activity schema. Logging by itself is not enough.

```lua
gtn.log("Activity loaded")

return {
    title = "Welcome to LiveOps",
    description = "A short activity description.",
    prompt = "Which statement is correct?",
    options = { "Correct answer", "Incorrect answer" },
    correct_option = 1,
    success_message = "Correct!",
    failure_message = "Try again."
}
```

- `title`, `description`, and `prompt` must be strings.
- `options` must contain 2–6 answer strings.
- `correct_option` is a **1-based** index into `options`.
- `success_message` and `failure_message` must be strings.
- The script's final result must be the table. Returning nothing or returning a different type causes the activity loader to reject it and fall back to the bundled featured activity.

The currently featured `scripts/welcome.lua` demonstrates this contract and logs a message to confirm the signed script ran.

## Signing and secrets

The publishing workflow signs the payload using the protected `LIVEOPS_PRIVATE_KEY_PEM` Actions secret. The Android app uses the matching public key supplied through the app repository's `LUA_LIVEOPS_PUBLIC_KEY_BASE64` Actions secret at build time.

**Never commit or paste the private signing key into source code, issues, pull requests, or logs.** If the signing key is rotated, update the corresponding app public-key secret and build a new APK with the matching public key.

For the wire format and client-side validation details, see the app repository's [Lua LiveOps Bundle Format documentation](https://github.com/ne0gl1tch20/GuessTheNumber/blob/master/docs/LIVEOPS_BUNDLE_FORMAT.md).
