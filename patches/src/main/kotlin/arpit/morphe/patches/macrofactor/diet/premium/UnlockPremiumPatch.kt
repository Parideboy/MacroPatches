package arpit.morphe.patches.macrofactor.diet.premium

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patches.all.misc.extension.sharedExtensionPatch
import app.morphe.patches.all.misc.fix.changepackageinstaller.changePackageInstallerPatch
import arpit.morphe.patches.macrofactor.diet.shared.Constants.COMPATIBILITY_MACROFACTOR_DIET
import arpit.morphe.patches.macrofactor.diet.shared.Constants.COMPATIBILITY_MACROFACTOR_DIET_5813
import arpit.morphe.patches.macrofactor.premium.BuildCustomerInfoFingerprint
import arpit.morphe.patches.macrofactor.premium.extensionPatch
import arpit.morphe.patches.macrofactor.signature.signatureHashSpoofPatch
import arpit.morphe.patches.macrofactor.signature.signatureHashSpoofShapePatch
import arpit.morphe.util.requireRootMount
import com.android.tools.smali.dexlib2.AccessFlags

private const val EXTENSION_CLASS = "Larpit/morphe/extension/macrofactor/diet/UnlockPremiumPatch;"

/**
 * MacroFactor (`com.sbs.diet`) premium unlock.
 *
 * Same RevenueCat boundary as the Workouts patch: every `CustomerInfo` is built by the
 * 5-arg `CustomerInfoFactory.buildCustomerInfo` overload, so rewriting the subscriber
 * JSON there covers the online, offline and cached parse paths.
 *
 * Verified against 5.8.11 (versionCode 883):
 * - `CustomerInfoFactory.buildCustomerInfo(JSONObject, Date, VerificationResult,
 *   CustomerInfoOriginalSource, Z)` in `classes6`, `.registers 20`, `public final`,
 *   filter order `subscriber` → `getJSONObject` → `non_subscriptions` → `subscriptions`
 *   → `entitlements` (filters are shared with the Workouts patch).
 * - `AndroidUtilsLight.getPackageCertificateHashBytes` in `classes4`, `.registers 3`.
 * - `FlutterFragmentActivity.onCreate(Bundle)` in `classes6`, `.registers 3`.
 *
 * The app keeps Firebase App Check (Play Integrity provider) and Play Billing, so a
 * re-signed sideload still fails attestation — root mount only.
 */
@Suppress("unused")
val unlockPremiumDietPatch = bytecodePatch(
    name = "Unlock Premium (Root)",
    description = "Unlocks all premium features. Requires root: the patched build must " +
        "be mounted over the genuine Play-signed install — a re-signed sideload " +
        "will not work.",
    default = true
) {
    compatibleWith(COMPATIBILITY_MACROFACTOR_DIET)

    availability(requireRootMount)

    dependsOn(
        // Shared extension module (context hook + both app extension classes).
        extensionPatch,
        // Computes the original cert SHA-1 from the input APK, so it works with this
        // app's own signing key (com.sbs.diet uses a different key than com.sbs.train).
        signatureHashSpoofPatch,
        changePackageInstallerPatch()
    )

    execute {
        // p1 is the JSONObject body; invoke-static writes no registers, so index 0 is safe.
        BuildCustomerInfoFingerprint.method.addInstructions(
            0,
            """
                invoke-static { p1 }, ${EXTENSION_CLASS}->updateCustomerInfo(Lorg/json/JSONObject;)V
            """
        )
    }
}

// Extension loading only: 5.8.13 renamed the Flutter activity
// (`MainActivity` now extends an obfuscated `Ls53;`, no `FlutterFragmentActivity` class
// left), so the activity context hook of [extensionPatch] cannot resolve there. The diet
// hook is context-free, so this variant loads the same extension module without a hook.
internal val dietExtensionPatchNoHook = sharedExtensionPatch("macrofactor")

/**
 * MacroFactor (`com.sbs.diet`) premium unlock for 5.8.13 (versionCode 893).
 *
 * Same injection point and same JSON rewrite as [unlockPremiumDietPatch], but everything is
 * resolved by shape because that build ships whole-dex R8 renaming: RevenueCat's
 * `CustomerInfoFactory.buildCustomerInfo` is `Lsob;->b(JSONObject, Date, Lw39;, Lvo1;, Z)Lmo1;`
 * and the GMS signature helper is `Ly6b;->a(Context, String)[B`.
 *
 * Verified shape matches against 5.8.13 (each resolves to exactly one method):
 * - customer-info builder: `.locals 17`, static, so the JSONObject body is `p0` (the 5.8.11
 *   build had it as `p1` in an instance method — the register is derived, not hardcoded);
 * - certificate hash helper: `.locals 4`, static, two parameters → `v0` free for the spoof.
 */
@Suppress("unused")
val unlockPremiumDiet5813Patch = bytecodePatch(
    name = "Unlock Premium (Root)",
    description = "Unlocks all premium features. Requires root: the patched build must " +
        "be mounted over the genuine Play-signed install — a re-signed sideload " +
        "will not work.",
    default = true
) {
    compatibleWith(COMPATIBILITY_MACROFACTOR_DIET_5813)

    availability(requireRootMount)

    dependsOn(
        dietExtensionPatchNoHook,
        signatureHashSpoofShapePatch,
        changePackageInstallerPatch()
    )

    execute {
        val customerInfoBuilder = BuildCustomerInfoShapeFingerprint.method

        // Static in 5.8.13 => the JSONObject is p0; instance => p1. invoke-static writes no
        // registers, so injecting at index 0 is safe either way. /range is required: with
        // `.locals 17` the parameter registers are v17/v18, past the v0-v15 limit of the
        // 3-register invoke format.
        val jsonRegister = if (AccessFlags.STATIC.isSet(customerInfoBuilder.accessFlags)) "p0" else "p1"

        customerInfoBuilder.addInstructions(
            0,
            """
                invoke-static/range { $jsonRegister .. $jsonRegister }, ${EXTENSION_CLASS}->updateCustomerInfo(Lorg/json/JSONObject;)V
            """
        )
    }
}
