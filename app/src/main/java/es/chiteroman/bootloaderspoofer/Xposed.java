package es.chiteroman.bootloaderspoofer;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {

    private static final KeyPair EC_KEYPAIR;
    private static final Map<Integer, ASN1Primitive> map = new HashMap<>();
    private static final SecureRandom random = new SecureRandom();
    private static byte[] attestationChallengeBytes = new byte[0];
    private static boolean brokenTEE = false;

    static {
        try {
            PEMParser parser = new PEMParser(new StringReader(Data.EC_PRIVATE_KEY));
            Object o = parser.readObject();
            parser.close();

            PEMKeyPair pemKeyPair = (PEMKeyPair) o;

            EC_KEYPAIR = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);

        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static X509CertificateHolder parseOtherCert(int num) {
        String str = "";

        if (num == 1) str = Data.CERT_1;
        else if (num == 2) str = Data.CERT_2;
        else if (num == 3) str = Data.CERT_3;

        try {
            PemReader reader = new PemReader(new StringReader(str));
            PemObject pemObject = reader.readPemObject();
            reader.close();

            return new X509CertificateHolder(pemObject.getContent());

        } catch (Exception e) {
            XposedBridge.log("ERROR, couldn't parse other cert " + num + " : " + e);
            throw new RuntimeException();
        }
    }

    private static Certificate[] getOtherCerts() throws Throwable {

        var holder_cert_1 = parseOtherCert(1);
        var holder_cert_2 = parseOtherCert(2);
        var holder_cert_3 = parseOtherCert(3);

        Certificate c1 = new JcaX509CertificateConverter().getCertificate(holder_cert_1);
        Certificate c2 = new JcaX509CertificateConverter().getCertificate(holder_cert_2);
        Certificate c3 = new JcaX509CertificateConverter().getCertificate(holder_cert_3);

        return new Certificate[]{c1, c2, c3};
    }

    private static ASN1Primitive getPrimitiveFromList(int tagNo) {

        if (map.containsKey(tagNo)) return map.get(tagNo);

        return null;
    }

    private static Extension addHackedExtension() {
        try {
            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            random.nextBytes(bytes1);
            random.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {
                    new DEROctetString(bytes1),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(bytes2)
            };

            ASN1Sequence rootOfTrustSeq = new DLSequence(rootOfTrustEncodables);

            ASN1Integer[] purposesArray = {
                    new ASN1Integer(2),
                    new ASN1Integer(3)
            };

            DLSet Apurpose = new DLSet(purposesArray);
            ASN1Integer Aalgorithm = new ASN1Integer(3);
            ASN1Integer AkeySize = new ASN1Integer(256);
            ASN1Integer AecCurve = new ASN1Integer(1);
            ASN1Null AnoAuthRequired = DERNull.INSTANCE;
            ASN1Integer AosVersion = new ASN1Integer(140000);
            ASN1Integer AosPatchLevel = new ASN1Integer(202312);
            ASN1Integer AvendorPatchLevel = new ASN1Integer(20231217);
            ASN1Integer AbootPatchLevel = new ASN1Integer(20231217);

            ASN1Primitive AcreationDateTime = null;
            ASN1Primitive Aorigin = null;
            ASN1Primitive AattestationApplicationId = null;

            if (!brokenTEE) {
                AcreationDateTime = getPrimitiveFromList(701);
                Aorigin = getPrimitiveFromList(702);
                AattestationApplicationId = getPrimitiveFromList(709);
            }

            var purpose = new DLTaggedObject(true, 1, Apurpose);
            var algorithm = new DLTaggedObject(true, 2, Aalgorithm);
            var keySize = new DLTaggedObject(true, 3, AkeySize);
            var ecCurve = new DLTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DLTaggedObject(true, 503, AnoAuthRequired);
            var rootOfTrust = new DLTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DLTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DLTaggedObject(true, 706, AosPatchLevel);
            var vendorPatchLevel = new DLTaggedObject(true, 718, AvendorPatchLevel);
            var bootPatchLevel = new DLTaggedObject(true, 719, AbootPatchLevel);

            ASN1TaggedObject creationDateTime = null;
            ASN1TaggedObject origin = null;
            ASN1TaggedObject attestationApplicationId = null;

            if (!brokenTEE) {
                creationDateTime = new DLTaggedObject(true, 701, AcreationDateTime);
                origin = new DLTaggedObject(true, 702, Aorigin);
                attestationApplicationId = new DLTaggedObject(true, 709, AattestationApplicationId);
            }

            ASN1Encodable[] teeEnforcedEncodables;

            if (brokenTEE) {
                teeEnforcedEncodables = new ASN1Encodable[]{
                        purpose,
                        algorithm,
                        keySize,
                        ecCurve,
                        noAuthRequired,
                        rootOfTrust,
                        osVersion,
                        osPatchLevel,
                        vendorPatchLevel,
                        bootPatchLevel
                };
            } else {
                teeEnforcedEncodables = new ASN1Encodable[]{
                        purpose,
                        algorithm,
                        keySize,
                        ecCurve,
                        noAuthRequired,
                        creationDateTime,
                        origin,
                        rootOfTrust,
                        osVersion,
                        osPatchLevel,
                        attestationApplicationId,
                        vendorPatchLevel,
                        bootPatchLevel
                };
            }

            ASN1Integer attestationVersion = new ASN1Integer(4);
            ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(2);
            ASN1Integer keymasterVersion = new ASN1Integer(41);
            ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(2);
            ASN1OctetString attestationChallenge = new DEROctetString(attestationChallengeBytes);
            ASN1OctetString uniqueId = new DEROctetString("".getBytes());
            ASN1Sequence softwareEnforced = new DLSequence();
            ASN1Sequence teeEnforced = new DLSequence(teeEnforcedEncodables);

            ASN1Encodable[] keyDescriptionEncodables = {
                    attestationVersion,
                    attestationSecurityLevel,
                    keymasterVersion,
                    keymasterSecurityLevel,
                    attestationChallenge,
                    uniqueId,
                    softwareEnforced,
                    teeEnforced
            };

            ASN1Sequence keyDescriptionHackSeq = new DLSequence(keyDescriptionEncodables);

            ASN1OctetString keyDescriptionOctetStr = new DEROctetString(keyDescriptionHackSeq);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), true, keyDescriptionOctetStr);

        } catch (Exception e) {
            XposedBridge.log("error create extensions: " + e);
        }

        return null;
    }

    private static void parseKeyDescription(ASN1Sequence keyDescription) {
        ASN1Sequence swEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(6).toASN1Primitive();
        ASN1Sequence teeEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(7).toASN1Primitive();

        for (ASN1Encodable encodable : swEnforcedAuthList) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) encodable;

            int tagNo = taggedObject.getTagNo();
            ASN1Primitive asn1Primitive = taggedObject.getBaseObject().toASN1Primitive();

            if (asn1Primitive == null) {
                XposedBridge.log("ERROR, couldn't parse " + tagNo + " object!");
            } else {
                map.put(tagNo, asn1Primitive);
            }
        }

        for (ASN1Encodable encodable : teeEnforcedAuthList) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) encodable;

            int tagNo = taggedObject.getTagNo();
            ASN1Primitive asn1Primitive = taggedObject.getBaseObject().toASN1Primitive();

            if (asn1Primitive == null) {
                XposedBridge.log("ERROR, couldn't parse " + tagNo + " object!");
            } else {
                map.put(tagNo, asn1Primitive);
            }
        }
    }

    private static Certificate brokenTeeLeafCert() throws Throwable {
        var certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=chiteroman"),
                new BigInteger(128, random),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                new X500Name("CN=Android Keystore Key"),
                EC_KEYPAIR.getPublic()
        );

        certBuilder.addExtension(addHackedExtension());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(EC_KEYPAIR.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    private static Certificate hackLeafCert(X509Certificate certificate) throws Throwable {
        var holder = new X509CertificateHolder(certificate.getEncoded());

        var certBuilder = new JcaX509v3CertificateBuilder(
                holder.getIssuer(),
                holder.getSerialNumber(),
                holder.getNotBefore(),
                holder.getNotAfter(),
                holder.getSubject(),
                EC_KEYPAIR.getPublic()
        );

        for (Object extensionOID : holder.getExtensionOIDs()) {

            ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) extensionOID;

            if ("1.3.6.1.4.1.11129.2.1.17".equals(identifier.getId())) continue;

            Extension e = holder.getExtension(identifier);

            certBuilder.addExtension(e);
        }

        Extension extension = holder.getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"));

        ASN1Sequence keyDescription = ASN1Sequence.getInstance(extension.getExtnValue().getOctets());

        parseKeyDescription(keyDescription);

        certBuilder.addExtension(addHackedExtension());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(EC_KEYPAIR.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> keyGenBuilder = XposedHelpers.findClass("android.security.keystore.KeyGenParameterSpec.Builder", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(keyGenBuilder, "setAttestationChallenge", byte[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    attestationChallengeBytes = (byte[]) param.args[0];
                    XposedBridge.log("attestationChallenge: " + Arrays.toString(attestationChallengeBytes));
                }
            });

            Class<?> keyPairGenerator = XposedHelpers.findClass("android.security.keystore2.AndroidKeyStoreKeyPairGeneratorSpi", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(keyPairGenerator, "generateKeyPair", XC_MethodReplacement.returnConstant(EC_KEYPAIR));

            Class<?> keyStoreSpi = XposedHelpers.findClass("android.security.keystore2.AndroidKeyStoreSpi", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(keyStoreSpi, "engineGetCertificateChain", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Certificate[] otherCerts = getOtherCerts();

                        Certificate[] hackCerts = new Certificate[4];

                        System.arraycopy(otherCerts, 0, hackCerts, 1, otherCerts.length);

                        Certificate[] certificates = (Certificate[]) param.getResult();

                        if (certificates == null || certificates.length == 0) {
                            brokenTEE = true;

                            XposedBridge.log("Uhhh, seems like you have a broken TEE.");
                            hackCerts[0] = brokenTeeLeafCert();

                        } else {
                            brokenTEE = false;

                            Certificate leaf = certificates[0];

                            if (!(leaf instanceof X509Certificate x509Certificate)) return;

                            byte[] bytes = x509Certificate.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");

                            if (bytes == null || bytes.length == 0) {
                                XposedBridge.log("Leaf certificate doesn't contain attestation extensions... Ignoring it.");
                                return;
                            }

                            hackCerts[0] = hackLeafCert(x509Certificate);
                        }

                        param.setResult(hackCerts);

                    } catch (Throwable t) {
                        XposedBridge.log("ERROR: " + t);
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log("ERROR: " + t);
        }
    }
}
