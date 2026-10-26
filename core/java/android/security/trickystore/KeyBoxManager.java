/*
 * Copyright (C) 2025-2026 AxionOS
 * Copyright (C) 2026 Evolution X
 * Copyright (C) 2026 HeckerOS
 * SPDX-License-Identifier: Apache-2.0
 * Adapted from Evolution-X/frameworks_base@6e9da54c4d0e71acca90091106c846919395410c.
 * Native private configuration and UID isolation remain owned by HeckerOS.
 */
package android.security.trickystore;

import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.ASN1InputStream;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.android.internal.org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import com.android.internal.org.bouncycastle.asn1.sec.ECPrivateKey;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @hide
 */
public class KeyBoxManager {
    private static final String TAG = "KeyBoxManager";

    private volatile String mLastError = "No supported key and certificate pair";
    public String getLastError() { return mLastError; }
    private boolean reject(String reason) { mLastError = reason; return false; }
    private volatile Map<String, KeyBox> mKeyboxes = new ConcurrentHashMap<>();

    private static final Pattern PEM_HEADER = Pattern.compile("-----BEGIN ([^-]+)-----");
    private static final Pattern XML_COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);

    /** @hide */
    public static class KeyBox {
        public final KeyPair keyPair;
        public final List<Certificate> certificates;
        private volatile X500Name mIssuerSubject;

        public KeyBox(KeyPair keyPair, List<Certificate> certificates) {
            this.keyPair = keyPair;
            this.certificates = certificates;
        }

        public X500Name getIssuerSubject() throws java.io.IOException,
                CertificateEncodingException {
            X500Name subject = mIssuerSubject;
            if (subject != null) return subject;
            synchronized (this) {
                subject = mIssuerSubject;
                if (subject == null) {
                    subject = new X509CertificateHolder(certificates.get(0).getEncoded())
                            .getSubject();
                    mIssuerSubject = subject;
                }
            }
            return subject;
        }
    }

    public void clear() {
        // Publish a fresh map instead of clearing the map a concurrent attestation
        // might already be reading.
        mKeyboxes = new ConcurrentHashMap<>();
        Log.i(TAG, "Keyboxes cleared");
    }

    public boolean hasKeyboxes() {
        return !mKeyboxes.isEmpty();
    }

    public KeyBox getKeybox(String algorithm) {
        return mKeyboxes.get(algorithm);
    }

    /**
     * Parses [xmlContent] and, if it is acceptable, replaces the loaded keyboxes.
     * A truncated or keyless document leaves the previously loaded keyboxes untouched,
     * so one bad refresh can't take attestation down.
     *
     * @return false if the document was rejected as incomplete, true otherwise
     */
    public boolean parseKeybox(String xmlContent) {
        // Parse into a private map and publish it at the end, so a concurrent
        // attestation never sees a half-filled or empty keybox mid-refresh.
        mLastError = "The keybox contains no supported EC or RSA key and certificate pair";
        Map<String, KeyBox> next = new ConcurrentHashMap<>();
        if (xmlContent != null && (xmlContent.length() > 256 * 1024
                || xmlContent.toUpperCase(java.util.Locale.ROOT).contains("<!DOCTYPE")
                || xmlContent.toUpperCase(java.util.Locale.ROOT).contains("<!ENTITY"))) return false;
        if (xmlContent == null || xmlContent.isEmpty()) {
            mKeyboxes = next;
            return true;
        }

        // Truncation is detected by well-formedness, not by NumberOfKeyboxes: the root
        // element must have closed for a parse failure to still be usable.
        int depth = 0;
        boolean rootClosed = false;

        try {
            xmlContent = sanitizeXml(xmlContent);
            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            XmlPullParser parser = factory.newPullParser();
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false);
            parser.setInput(new StringReader(xmlContent));

            int currentKeyIndex = -1;
            String currentAlgorithm = null;
            String privateKeyPem = null;
            List<String> certificatePems = new ArrayList<>();
            StringBuilder privateKeyBuilder = null;
            StringBuilder certBuilder = null;
            boolean inKey = false;
            boolean inPrivateKey = false;
            boolean inCertificateChain = false;
            boolean inCertificate = false;
            boolean inNumberOfKeyboxes = false;
            StringBuilder numberOfKeyboxesBuilder = null;
            Integer declaredKeyboxCount = null;
            // NumberOfKeyboxes counts <Keybox> elements, each of which normally holds
            // both an ECDSA and an RSA <Key>, so count boxes and not keys.
            int parsedKeyboxCount = 0;
            boolean sawKeyboxTag = false;
            boolean boxHasKey = false;
            int parsedKeyCount = 0;

            int eventType = parser.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                String tagName = parser.getName();
                if (eventType == XmlPullParser.START_TAG && rootClosed && depth == 0) return false;
                if (eventType == XmlPullParser.TEXT && depth == 0
                        && !parser.getText().trim().isEmpty()) return false;
                if (eventType == XmlPullParser.START_TAG) {
                    depth++;
                } else if (eventType == XmlPullParser.END_TAG && --depth == 0) {
                    rootClosed = true;
                }

                switch (eventType) {
                    case XmlPullParser.START_TAG:
                        if ("Keybox".equals(tagName)) {
                            sawKeyboxTag = true;
                            boxHasKey = false;
                        } else if ("Key".equals(tagName)) {
                            inKey = true;
                            currentKeyIndex++;
                            currentAlgorithm = parser.getAttributeValue(null, "algorithm");
                            privateKeyPem = null;
                            certificatePems.clear();
                            privateKeyBuilder = null;
                            certBuilder = null;
                        } else if ("PrivateKey".equals(tagName) && inKey) {
                            inPrivateKey = true;
                            privateKeyBuilder = new StringBuilder();
                        } else if ("CertificateChain".equals(tagName) && inKey) {
                            inCertificateChain = true;
                        } else if ("Certificate".equals(tagName) && inCertificateChain) {
                            inCertificate = true;
                            certBuilder = new StringBuilder();
                        } else if ("NumberOfKeyboxes".equals(tagName) && !inKey) {
                            inNumberOfKeyboxes = true;
                            numberOfKeyboxesBuilder = new StringBuilder();
                        }
                        break;

                    case XmlPullParser.TEXT:
                        String text = parser.getText();
                        if (text != null) {
                            if (inPrivateKey && privateKeyBuilder != null) {
                                privateKeyBuilder.append(text);
                            } else if (inCertificate && certBuilder != null) {
                                certBuilder.append(text);
                            } else if (inNumberOfKeyboxes && numberOfKeyboxesBuilder != null) {
                                numberOfKeyboxesBuilder.append(text);
                            }
                        }
                        break;

                    case XmlPullParser.END_TAG:
                        if ("PrivateKey".equals(tagName)) {
                            if (privateKeyBuilder != null) {
                                String pem = privateKeyBuilder.toString().trim();
                                if (!pem.isEmpty()) {
                                    privateKeyPem = pem;
                                }
                                privateKeyBuilder = null;
                            }
                            inPrivateKey = false;
                        } else if ("Certificate".equals(tagName)) {
                            if (certBuilder != null) {
                                String pem = certBuilder.toString().trim();
                                if (!pem.isEmpty()) {
                                    certificatePems.add(pem);
                                }
                                certBuilder = null;
                            }
                            inCertificate = false;
                        } else if ("CertificateChain".equals(tagName)) {
                            inCertificateChain = false;
                        } else if ("NumberOfKeyboxes".equals(tagName)) {
                            if (numberOfKeyboxesBuilder != null) {
                                try {
                                    declaredKeyboxCount =
                                            Integer.parseInt(numberOfKeyboxesBuilder.toString().trim());
                                } catch (NumberFormatException ignored) {
                                }
                                numberOfKeyboxesBuilder = null;
                            }
                            inNumberOfKeyboxes = false;
                        } else if ("Key".equals(tagName)) {
                            inKey = false;
                            if (currentAlgorithm != null && privateKeyPem != null && !certificatePems.isEmpty()) {
                                if (!processKeybox(next, currentAlgorithm, privateKeyPem, certificatePems)) return false;
                                parsedKeyCount++;
                                boxHasKey = true;
                            }
                        } else if ("Keybox".equals(tagName)) {
                            if (boxHasKey) parsedKeyboxCount++;
                            boxHasKey = false;
                        }
                        break;
                }

                eventType = parser.next();
            }

            // A document without <Keybox> wrappers holds a single implicit box.
            if (!sawKeyboxTag && parsedKeyCount > 0) parsedKeyboxCount = 1;
            // NumberOfKeyboxes is advisory. Generators disagree on what it counts (the
            // <Keybox> wrappers or the <Key> elements) and some write a value that matches
            // neither, which TEESimulator-RS and AlwaysStrong accept as well: they iterate
            // every <Key> they find. So a mismatch is only logged. A truncated download is
            // caught by the parse failure below, and a document that yields no key at all
            // is still rejected so it can't wipe the loaded keyboxes.
            if (declaredKeyboxCount != null && declaredKeyboxCount > 0 && parsedKeyCount == 0) {
                Log.e(TAG, "Keybox XML declares " + declaredKeyboxCount
                        + " keybox(es) but no complete key parsed — rejecting, keeping the"
                        + " current keyboxes");
                return false;
            }
            if (declaredKeyboxCount != null
                    && declaredKeyboxCount != parsedKeyboxCount
                    && declaredKeyboxCount != parsedKeyCount) {
                Log.w(TAG, "Keybox XML declares " + declaredKeyboxCount + " keybox(es), parsed "
                        + parsedKeyboxCount + " box(es) / " + parsedKeyCount
                        + " key(s); NumberOfKeyboxes is advisory, using what parsed");
            }

            if (!rootClosed || depth != 0) return reject("The keybox XML is incomplete or malformed");
            if (next.isEmpty()) return false;
            mKeyboxes = next;
            Log.i(TAG, "Parsed " + next.size() + " keyboxes");
            return true;
        } catch (Exception e) {
            mLastError = "The keybox XML is incomplete or malformed";
            Log.e(TAG, mLastError);
            // A failed parse never publishes a partial or trailing-garbage document.
            // This also protects the private importer, which starts with an empty map.
            return false;
        }
    }

    private boolean processKeybox(Map<String, KeyBox> target, String algorithm, String privateKeyPem,
            List<String> certificatePems) {
        String normalizedAlgorithm;
        switch (algorithm.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "ec": case "ecdsa": normalizedAlgorithm = "EC"; break;
            case "rsa": normalizedAlgorithm = "RSA"; break;
            default: return reject("Only EC/ECDSA and RSA private keys are supported");
        }
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            List<Certificate> certificates = new ArrayList<>();
            for (String certPem : certificatePems) {
                certificates.add(certFactory.generateCertificate(new ByteArrayInputStream(parsePemContent(certPem))));
            }
            if (certificates.isEmpty()) return reject("The keybox contains no X.509 certificates");
            PublicKey publicKey = certificates.get(0).getPublicKey();
            PrivateKey privateKey = parsePrivateKey(privateKeyPem, normalizedAlgorithm, publicKey);
            byte[] proof = new byte[32]; new java.security.SecureRandom().nextBytes(proof);
            java.security.Signature signature = java.security.Signature.getInstance(
                    "RSA".equals(normalizedAlgorithm) ? "SHA256withRSA" : "SHA256withECDSA");
            signature.initSign(privateKey); signature.update(proof); byte[] signed = signature.sign();
            signature.initVerify(publicKey); signature.update(proof);
            if (!signature.verify(signed)) return reject("The private key does not match its first certificate");
            target.put(normalizedAlgorithm, new KeyBox(new KeyPair(publicKey, privateKey), certificates));
            return true;
        } catch (java.security.cert.CertificateException badCertificate) {
            return reject("A keybox certificate is not a valid X.509 certificate");
        } catch (java.security.InvalidKeyException mismatch) {
            return reject("The private key algorithm or curve does not match its first certificate");
        } catch (Exception invalidKey) {
            return reject("The private key could not be decoded; use unencrypted PKCS#8, SEC1 EC or PKCS#1 RSA");
        }
    }

    private PrivateKey parsePrivateKey(String pem, String algorithm, PublicKey certificateKey) throws Exception {
        String pemType = detectPemType(pem);
        if ("ENCRYPTED PRIVATE KEY".equals(pemType)) throw new java.security.spec.InvalidKeySpecException();
        byte[] keyBytes = parsePemContent(pem);
        // JCA returns a key understood by Android's active signing provider. Do not
        // construct a repackaged Bouncy Castle provider key with a null configuration.
        if (!"EC PRIVATE KEY".equals(pemType) && !"RSA PRIVATE KEY".equals(pemType)) {
            try { return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(keyBytes)); }
            catch (java.security.spec.InvalidKeySpecException notPkcs8) { }
        }
        return "EC".equals(algorithm) ? parseEcPrivateKey(keyBytes, certificateKey) : parseRsaPrivateKey(keyBytes);
    }

    private PrivateKey parseEcPrivateKey(byte[] keyBytes, PublicKey certificateKey) throws Exception {
        if (!(certificateKey instanceof java.security.interfaces.ECPublicKey)) {
            throw new java.security.InvalidKeyException();
        }
        ECPrivateKey sec1 = ECPrivateKey.getInstance(keyBytes);
        // SEC1 allows its curve parameters to be omitted. The matching leaf certificate
        // already supplies the curve; the sign/verify check above still proves the pair.
        java.security.spec.ECParameterSpec parameters =
                ((java.security.interfaces.ECPublicKey) certificateKey).getParams();
        return KeyFactory.getInstance("EC").generatePrivate(
                new java.security.spec.ECPrivateKeySpec(sec1.getKey(), parameters));
    }

    private PrivateKey parseRsaPrivateKey(byte[] keyBytes) throws Exception {
        try (ASN1InputStream asn1In = new ASN1InputStream(keyBytes)) {
            ASN1Primitive asn1 = asn1In.readObject();
            try {
                RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(asn1);
                RSAPrivateCrtKeySpec rsaSpec = new RSAPrivateCrtKeySpec(
                        rsaPrivateKey.getModulus(),
                        rsaPrivateKey.getPublicExponent(),
                        rsaPrivateKey.getPrivateExponent(),
                        rsaPrivateKey.getPrime1(),
                        rsaPrivateKey.getPrime2(),
                        rsaPrivateKey.getExponent1(),
                        rsaPrivateKey.getExponent2(),
                        rsaPrivateKey.getCoefficient());
                return KeyFactory.getInstance("RSA").generatePrivate(rsaSpec);
            } catch (Exception e) {
                PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(asn1);
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            }
        }
    }

    private String detectPemType(String pem) {
        if (pem == null) return null;
        Matcher m = PEM_HEADER.matcher(pem);
        return m.find() ? m.group(1).trim().toUpperCase() : null;
    }

    private byte[] parsePemContent(String pem) {
        String base64 = pem
            .replaceAll("-----BEGIN [^-]+-----", "")
            .replaceAll("-----END [^-]+-----", "")
            .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private String sanitizeXml(String content) {
        content = content.trim();
        String[] boms = {"\uFEFF", "\uFFFE", "\u0000\uFEFF"};
        for (String bom : boms) {
            if (content.startsWith(bom)) {
                content = content.substring(bom.length());
            }
        }
        content = XML_COMMENT.matcher(content).replaceAll("");
        return content.trim();
    }
}
