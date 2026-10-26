package android.security.pif;
import java.lang.reflect.Method;
public final class PlayIntegrityScopeTest {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    public static void main(String[] args) throws Exception {
        PlayIntegritySpoofService p = PlayIntegritySpoofService.getInstance();
        check(!p.shouldSpoof("com.google.android.gms.unstable"), "disabled until profile loads");
        p.loadConfig("FINGERPRINT=google/shiba_beta/shiba:17/CP21/123456:user/release-keys\n"
                +"MODEL=Pixel 8\nSECURITY_PATCH=2026-05-05\nspoofProvider=false\nspoofSignature=false\n");
        check(p.shouldSpoof("com.google.android.gms.unstable"), "attestation target");
        check(p.shouldSpoof("com.android.vending"), "Play Store target");
        for(String other:new String[]{"com.android.settings","org.hecker.suite",
                "com.google.android.gms","com.google.android.gms.persistent","app.third.party"}) {
            check(!p.shouldSpoof(other), "unrelated process must remain unchanged: "+other);
        }
        check("google".equals(p.getBuildFields().get("BRAND")), "fingerprint expansion");
        check("17".equals(p.getBuildFields().get("RELEASE")), "Android release parsing");
        check(!p.isSpoofProviderEnabled()&&!p.isSpoofSignatureEnabled(), "upstream opt-in flags");
        Method sdk=PlayIntegritySpoofService.class.getDeclaredMethod("resolveDeviceInitialSdk",String.class,String.class);
        sdk.setAccessible(true);
        check("34".equals(sdk.invoke(null,"shiba","32")), "initial API follows selected Pixel model");
        check("35".equals(sdk.invoke(null,"stallion","32")), "latest device mapping");
        p.loadConfig("FINGERPRINT=google/shiba/shiba:17/CP21/123456:user/release-keys\n"
                +"spoofProvider=true\nspoofSignature=true\nspoofVendingSdk=35\nspoofVendingFinger=1\n");
        check(p.isConfigLoaded()&&p.isSpoofProviderEnabled(), "current Evolution X numeric options");
        check("1".equals(p.getSpoofVendingFinger()), "Play Store fingerprint option is retained");
        p.loadConfig("FINGERPRINT=google/shiba/shiba:17/CP21/123456:user/release-keys\n");
        check(!p.isSpoofProviderEnabled()&&!p.isSpoofSignatureEnabled(), "a replacement profile resets opt-in flags");
        check("0".equals(p.getSpoofVendingFinger()), "Play Store spoofing defaults off like Evolution X");
        p.loadConfig("");
        check(!p.isConfigLoaded()&&!p.shouldSpoof("com.android.vending"), "disabled profile is inert");
        p.loadConfig("MODEL=Incomplete profile\n");
        check(!p.isConfigLoaded(), "incomplete profile must not enable native property rules");
        System.out.println("Evolution X PIF parser and process scope: PASS");
    }
}
