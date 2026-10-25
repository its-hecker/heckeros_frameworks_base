/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.spoof;

import android.app.ActivityManager;
import android.app.IActivityManager;
import android.content.Context;
import android.os.Binder;
import android.os.Environment;
import android.os.FileUtils;
import android.security.gameprops.GamePropsSpoofService;
import android.security.spoof.HeckerSpoofConfig;
import android.security.trickystore.AttestationUtils;
import android.security.trickystore.CertificateGenerator;
import android.security.trickystore.CertificateHacker;
import android.security.trickystore.KeyBoxManager;
import android.security.trickystore.TrickyStoreService;

import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1Set;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/** Synthetic keys exist only in this temporary host run; none are shipped. */
public final class SpoofingConfigTest {
    private static int checks;
    private static void check(boolean condition, String name) {
        checks++;
        if (!condition) throw new AssertionError(name);
    }
    private static void rejected(Runnable operation, String name) {
        try { operation.run(); throw new AssertionError(name); }
        catch (IllegalArgumentException | SecurityException | IllegalStateException expected) { checks++; }
    }
    private static KeyPair keys(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if (algorithm.equals("EC")) generator.initialize(new ECGenParameterSpec("secp256r1"));
        else generator.initialize(2048);
        return generator.generateKeyPair();
    }
    private static Certificate certificate(KeyPair pair, String algorithm) throws Exception {
        X500Name name = new X500Name("CN=Ephemeral HeckerOS Host Test");
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name, BigInteger.ONE,
                new Date(0), new Date(4102444800000L), name,
                SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
        byte[] der = builder.build(new JcaContentSignerBuilder(algorithm.equals("EC")
                ? "SHA256withECDSA" : "SHA256withRSA").build(pair.getPrivate())).getEncoded();
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }
    private static String pem(String type, byte[] value) {
        return "-----BEGIN "+type+"-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'})
                .encodeToString(value)+"\n-----END "+type+"-----";
    }
    private static String keybox(KeyPair keys, Certificate cert, String algorithm) throws Exception {
        return "<Key algorithm=\""+algorithm+"\"><PrivateKey>"+pem("PRIVATE KEY",keys.getPrivate().getEncoded())
                +"</PrivateKey><CertificateChain><Certificate>"+pem("CERTIFICATE",cert.getEncoded())
                +"</Certificate></CertificateChain></Key>";
    }

    public static void main(String[] args) throws Exception {
        Environment.data = new java.io.File(args[0]);
        Files.createDirectories(Environment.data.toPath());
        Context context = new Context();
        context.packages.names.put(10001,new String[]{"com.game.alpha"});
        context.packages.names.put(10002,new String[]{"com.check.beta"});
        context.packages.names.put(10003,new String[]{"com.other.app"});
        context.packages.names.put(110001,new String[]{"com.game.alpha"});
        HeckerSpoofConfigStore store = new HeckerSpoofConfigStore(context);
        String game = "{\"enabled\":true,\"games\":{\"com.game.alpha\":{\"MODEL\":\"Test Model\"},"
                +"\"com.check.beta\":{\"MODEL\":\"Other Model\"}}}";
        Binder.uid=1000;
        store.put(HeckerSpoofConfig.GAMES,game);
        store.put(HeckerSpoofConfig.TARGETS,"com.game.alpha!\ncom.check.beta?");
        store.put(HeckerSpoofConfig.PATCH,"all=2026-10-05");
        check(FileUtils.mode==0600,"private file permissions requested");
        String storedGame=store.getForSettings(1);
        for (String invalid : List.of("{", "{\"games\":{\"bad name\":{}}}",
                "{\"games\":{\"com.game.alpha\":{\"SDK_INT\":\"30\"}}}",
                "{\"games\":{\"com.game.alpha\":{\"MODEL\":123}}}")) {
            rejected(()->store.put(1,invalid),"invalid game rejected atomically");
            check(storedGame.equals(store.getForSettings(1)),"invalid import keeps previous config");
        }
        rejected(()->store.put(2,"com.bad name!"),"invalid target package");
        rejected(()->store.put(2,"[{\"package\":\"com.game.alpha\",\"mode\":\"BAD\"}]"),"invalid target mode");
        rejected(()->store.put(4,"all=2026-02-30"),"invalid calendar date");
        rejected(()->store.put(3,"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>"),"XML entity rejection");
        rejected(()->store.put(1,"x".repeat(HeckerSpoofConfig.MAX_BYTES+1)),"size cap");
        FileUtils.fail=1;
        rejected(()->store.put(1,"{\"games\":{}}"),"write failure");
        FileUtils.fail=0;
        check(storedGame.equals(store.getForSettings(1)),"failed write keeps cache");
        check(storedGame.equals(new HeckerSpoofConfigStore(context).getForSettings(1)),"failed write rolls back disk");
        check(Binder.uid==1000,"Binder identity restored");

        KeyPair ec=keys("EC"), rsa=keys("RSA");
        Certificate ecCert=certificate(ec,"EC"), rsaCert=certificate(rsa,"RSA");
        android.app.ActivityThread.packages=new android.content.pm.IPackageManager() {
            public String[] getPackagesForUid(int uid){return context.packages.names.get(uid);}
            public android.content.pm.PackageInfo getPackageInfo(String name,long flags,int user) {
                android.content.pm.PackageInfo info=new android.content.pm.PackageInfo();
                try { info.signingInfo=new android.content.pm.SigningInfo(
                        new android.content.pm.Signature(ecCert.getEncoded())); }
                catch (Exception impossible) { throw new AssertionError(impossible); }
                return info;
            }
        };
        String xml="<AndroidAttestation>"+keybox(ec,ecCert,"ec")+keybox(rsa,rsaCert,"rsa")+"</AndroidAttestation>";
        store.put(3,Base64.getEncoder().encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        check(store.getForCaller(3)==null,"system services do not enter app certificate hooks");
        KeyBoxManager manager=new KeyBoxManager();
        manager.parseKeybox(xml);
        check(manager.getKeybox("EC")!=null&&manager.getKeybox("RSA")!=null,"RSA and EC imported");
        manager.parseKeybox("<a>"+keybox(keys("EC"),ecCert,"ec")+"</a>");
        check(!manager.hasKeyboxes(),"private key must match certificate");
        manager.parseKeybox("<a><Key algorithm=\"ec\"><PrivateKey>bad</PrivateKey></Key></a>");
        check(!manager.hasKeyboxes(),"invalid keybox clears state");

        Binder.uid=10003;
        check(store.getForCaller(1)==null&&store.getForCaller(2)==null&&store.getForCaller(3)==null,"unselected UID sees nothing");
        rejected(()->store.getForSettings(3),"unprivileged management read denied");
        rejected(()->store.put(2,"com.other.app!"),"unprivileged management write denied");
        Binder.uid=110001;
        check(store.getForCaller(3)==null,"secondary profile excluded");
        Binder.uid=10001;
        check(store.getForCaller(1).contains("com.game.alpha")&&!store.getForCaller(1).contains("com.check.beta"),"game read scoped to own UID");
        check(store.getForCaller(2).contains("GENERATE")&&!store.getForCaller(2).contains("com.check.beta"),"target read scoped to own UID");
        check(store.getForCaller(3).equals(xml),"selected UID receives imported keybox");

        String[] gameOverride={null};
        ActivityManager.service=new IActivityManager() {
            public String getSpoofGamePropsConfig(){return gameOverride[0]!=null?gameOverride[0]:store.getForCaller(1);}
            public String getSpoofTrickyStoreTarget(){return store.getForCaller(2);}
            public String getSpoofTrickyStoreKeyBox(){return store.getForCaller(3);}
            public String getSpoofTrickyStorePatch(){return store.getForCaller(4);}
            public String getHeckerSpoofConfig(int k){return store.getForSettings(k);}
            public void setHeckerSpoofConfig(int k,String v){store.put(k,v);}
        };
        GamePropsSpoofService games=GamePropsSpoofService.getInstance();
        games.spoofForPackage("com.other.app");
        check(android.os.Build.MODEL.equals("Original"),"unlisted game stays native");
        games.spoofForPackage("com.game.alpha");
        check(android.os.Build.MODEL.equals("Test Model"),"selected game receives profile");
        gameOverride[0]="{\"enabled\":true,\"games\":{\"com.game.alpha\":{\"MODEL\":\"Incomplete\"}}";
        games.loadConfig();
        check(!games.isEnabled()&&games.getAllGameConfigs().isEmpty(),"malformed game profile is inert");
        gameOverride[0]=null;

        TrickyStoreService tricky=TrickyStoreService.getInstance();
        check(tricky.needGenerate(10001,new String[]{"com.game.alpha"}),"explicit generation mode");
        check(!tricky.needHack(10001,new String[]{"com.game.alpha"}),"generation does not also replace leaf");
        check(!tricky.needGenerate(10001,new String[]{"com.other.app"}),"unlisted package never generates");
        check(AttestationUtils.getOsVersion()==170000,"Android 17 OS version");
        check(AttestationUtils.getPatchLevel(false)==202610&&AttestationUtils.getBootPatchLevel(true)==20261005,"patch imports parsed");
        for (String algorithm : List.of("EC","RSA")) {
            CertificateGenerator.KeyGenParameters parameters=new CertificateGenerator.KeyGenParameters();
            parameters.algorithm=algorithm.equals("EC")?3:1;
            parameters.keySize=algorithm.equals("EC")?256:2048;
            parameters.ecCurveName="secp256r1";
            parameters.ecCurve=android.hardware.security.keymint.EcCurve.P_256;
            parameters.rsaPublicExponent=BigInteger.valueOf(65537);
            parameters.attestationChallenge=new byte[]{1,2,3,4};
            KeyPair leaf=CertificateGenerator.generateKeyPair(parameters);
            check(leaf!=null,"software key generated: "+algorithm);
            List<Certificate> chain=CertificateGenerator.generateCertificateChain(leaf,parameters,1,10001);
            check(chain!=null&&chain.size()==2,"certificate chain generated: "+algorithm);
            chain.get(0).verify(algorithm.equals("EC")?ec.getPublic():rsa.getPublic());
            check(java.util.Arrays.equals(chain.get(0).getPublicKey().getEncoded(),leaf.getPublic().getEncoded()),"leaf key preserved: "+algorithm);
            ASN1Sequence description=ASN1Sequence.getInstance(new X509CertificateHolder(chain.get(0).getEncoded())
                    .getExtension(CertificateGenerator.ATTESTATION_OID).getParsedValue());
            check(java.util.Arrays.equals(ASN1OctetString.getInstance(description.getObjectAt(4)).getOctets(),
                    parameters.attestationChallenge),"attestation challenge preserved: "+algorithm);
            boolean identity=false;
            for (var entry : ASN1Sequence.getInstance(description.getObjectAt(6))) {
                ASN1TaggedObject tagged=ASN1TaggedObject.getInstance(entry);
                if (tagged.getTagNo()!=709) continue;
                ASN1Sequence appId=ASN1Sequence.getInstance(ASN1OctetString.getInstance(tagged,true).getOctets());
                ASN1Sequence app=ASN1Sequence.getInstance(ASN1Set.getInstance(appId.getObjectAt(0)).getObjectAt(0));
                String name=new String(ASN1OctetString.getInstance(app.getObjectAt(0)).getOctets(),java.nio.charset.StandardCharsets.UTF_8);
                byte[] digest=ASN1OctetString.getInstance(ASN1Set.getInstance(appId.getObjectAt(1)).getObjectAt(0)).getOctets();
                identity=name.equals("com.game.alpha")&&java.util.Arrays.equals(digest,
                        java.security.MessageDigest.getInstance("SHA-256").digest(ecCert.getEncoded()));
            }
            check(identity,"package name and real signing digest: "+algorithm);
            Certificate[] original=chain.toArray(new Certificate[0]);
            Certificate[] hacked=CertificateHacker.hackCertificateChain(original);
            check(hacked!=null&&hacked!=original&&hacked.length==2,"certificate replacement: "+algorithm);
            hacked[0].verify(algorithm.equals("EC")?ec.getPublic():rsa.getPublic());
            check(java.util.Arrays.equals(hacked[0].getPublicKey().getEncoded(),leaf.getPublic().getEncoded()),"replacement preserves key: "+algorithm);
        }
        Binder.uid=10002;
        check(tricky.needHack(10002,new String[]{"com.check.beta"}),"explicit leaf replacement mode");
        check(!tricky.needGenerate(10002,new String[]{"com.check.beta"}),"leaf mode does not generate");
        Binder.uid=10003;
        check(!tricky.hasKeyboxes(),"unselected process cannot retain another caller's keybox");
        Binder.uid=1000;
        store.put(HeckerSpoofConfig.OPTIONS,"{\"trickystore_enabled\":false}");
        Binder.uid=10001;
        check(store.getForCaller(2)==null&&store.getForCaller(3)==null&&store.getForCaller(4)==null,"master switch gates targets, private keys and patch");
        check(store.getForCaller(1)!=null,"TrickyStore master does not disable game profiles");
        check(store.getForCaller(HeckerSpoofConfig.OPTIONS)==null,"private options are not exposed to app callers");
        Binder.uid=1000;
        check(store.getForSettings(3).equals(xml),"disable preserves the imported keybox");
        store.put(HeckerSpoofConfig.OPTIONS,"{\"trickystore_enabled\":true}");
        store.put(HeckerSpoofConfig.TARGETS,"com.game.alpha-\ncom.check.beta?");
        Binder.uid=10001;
        check(store.getForCaller(2).contains("SKIP"),"Evolution X skip suffix is canonicalized");
        check(store.getForCaller(3)==null&&store.getForCaller(4)==null,"Skip does not disclose private keys or patch data");
        check(!tricky.needHack(10001,new String[]{"com.game.alpha"})&&!tricky.needGenerate(10001,new String[]{"com.game.alpha"}),"Skip leaves the native chain untouched");
        Binder.uid=1000;
        store.put(HeckerSpoofConfig.TARGETS,"org.lsposed.manager!\ncom.game.alpha!");
        context.packages.names.put(10004,new String[]{"org.lsposed.manager"});Binder.uid=10004;
        check(store.getForCaller(3)==null,"Xposed managers remain excluded even after a target import");
        Binder.uid=1000;
        rejected(()->store.put(HeckerSpoofConfig.OPTIONS,"{\"trickystore_enabled\":\"true\"}"),"master option requires a boolean");
        rejected(()->store.put(HeckerSpoofConfig.OPTIONS,"{\"trickystore_enabled\":true,\"other\":true}"),"unknown option rejected");
        store.put(3,null);
        Binder.uid=10001;
        check(!tricky.hasKeyboxes()&&!tricky.needGenerate(10001,new String[]{"com.game.alpha"}),"removing keybox disables certificate path");
        System.out.println(checks+" configuration, access, parser, game and RSA/EC chain checks: PASS");
    }
}
