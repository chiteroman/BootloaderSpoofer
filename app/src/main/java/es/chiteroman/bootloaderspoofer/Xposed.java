package es.chiteroman.bootloaderspoofer;

import android.app.AndroidAppHelper;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
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
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {
    private static final String TAG = "BootloaderSpoofer";
    private static final KeyPair EC_KEYPAIR, RSA_KEYPAIR;
    private static final Certificate[] certsChain = new Certificate[3];
    private static final SecureRandom random = new SecureRandom();
    private static byte[] attestationChallengeBytes = new byte[0];
    private static Signature[] signatures;
    private static int versionCode;
    private static String packageName;

    static {
        try {
            Object o;
            PEMKeyPair pemKeyPair;

            try (PEMParser parser = new PEMParser(new StringReader(Data.EC_PRIVATE_KEY))) {
                o = parser.readObject();
            }

            pemKeyPair = (PEMKeyPair) o;

            EC_KEYPAIR = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);

            try (PEMParser parser = new PEMParser(new StringReader(Data.RSA_PRIVATE_KEY))) {
                o = parser.readObject();
            }

            pemKeyPair = (PEMKeyPair) o;

            RSA_KEYPAIR = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);

            certsChain[0] = parseOtherCert(Data.CERT_1);
            certsChain[1] = parseOtherCert(Data.CERT_2);
            certsChain[2] = parseOtherCert(Data.CERT_3);

        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static Certificate parseOtherCert(String cert) throws Exception {

        PemReader reader = new PemReader(new StringReader(cert));
        PemObject pemObject = reader.readPemObject();
        reader.close();

        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());

        return new JcaX509CertificateConverter().getCertificate(holder);
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

            ASN1Integer AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            ASN1Integer Aorigin = new ASN1Integer(0);

            var purpose = new DLTaggedObject(true, 1, Apurpose);
            var algorithm = new DLTaggedObject(true, 2, Aalgorithm);
            var keySize = new DLTaggedObject(true, 3, AkeySize);
            var ecCurve = new DLTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DLTaggedObject(true, 503, AnoAuthRequired);
            var creationDateTime = new DLTaggedObject(true, 701, AcreationDateTime);
            var origin = new DLTaggedObject(true, 702, Aorigin);
            var rootOfTrust = new DLTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DLTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DLTaggedObject(true, 706, AosPatchLevel);
            var vendorPatchLevel = new DLTaggedObject(true, 718, AvendorPatchLevel);
            var bootPatchLevel = new DLTaggedObject(true, 719, AbootPatchLevel);

            ASN1Encodable[] teeEnforcedEncodables = {
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
                    vendorPatchLevel,
                    bootPatchLevel
            };

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
            Log.e(TAG, "error create extensions: " + e);
        }

        return null;
    }

    private static Certificate hackLeafCert() throws Exception {

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

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {

        PackageManager packageManager = AndroidAppHelper.currentApplication().getPackageManager();

        PackageInfo packageInfo = packageManager.getPackageInfo(lpparam.packageName, 0);

        packageName = lpparam.packageName;
        signatures = packageInfo.signatures;
        versionCode = packageInfo.versionCode;

        Class<?> AndroidKeyStoreKeyPairGeneratorSpi = XposedHelpers.findClassIfExists("android.security.keystore2.AndroidKeyStoreKeyPairGeneratorSpi", lpparam.classLoader);

        if (AndroidKeyStoreKeyPairGeneratorSpi == null) {

            KeyPairGenerator keyPairGenerator1 = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGenerator1.getClass(), "generateKeyPair", XC_MethodReplacement.returnConstant(EC_KEYPAIR));
            XposedHelpers.findAndHookMethod(keyPairGenerator1.getClass(), "genKeyPair", XC_MethodReplacement.returnConstant(EC_KEYPAIR));

            KeyPairGenerator keyPairGenerator2 = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGenerator2.getClass(), "generateKeyPair", XC_MethodReplacement.returnConstant(RSA_KEYPAIR));
            XposedHelpers.findAndHookMethod(keyPairGenerator1.getClass(), "genKeyPair", XC_MethodReplacement.returnConstant(RSA_KEYPAIR));

        } else {
            XposedHelpers.findAndHookMethod(AndroidKeyStoreKeyPairGeneratorSpi, "generateKeyPair", XC_MethodReplacement.returnConstant(EC_KEYPAIR));
        }

        XposedHelpers.findAndHookMethod(KeyGenParameterSpec.Builder.class, "setAttestationChallenge", byte[].class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                attestationChallengeBytes = (byte[]) param.args[0];
                Log.d(TAG, "attestationChallenge: " + Arrays.toString(attestationChallengeBytes));
            }
        });

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
        XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Certificate[] certificates = null;

                try {
                    certificates = (Certificate[]) param.getResultOrThrowable();
                } catch (Throwable e) {
                    XposedBridge.log("Couldn't get original certificate chain, broken TEE ?");
                }

                Certificate[] hackCerts = new Certificate[4];

                System.arraycopy(certsChain, 0, hackCerts, 1, certsChain.length);

                if (certificates != null && certificates.length > 1) {

                    Certificate leaf = certificates[0];

                    if (!(leaf instanceof X509Certificate x509Certificate)) return;

                    byte[] bytes = x509Certificate.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");

                    if (bytes == null || bytes.length == 0) {
                        XposedBridge.log("Leaf certificate doesn't contain attestation extensions... Ignoring it.");
                        return;
                    }

                } else {
                    Log.d(TAG, "Original certificate chain is null or empty... Broken TEE ?");
                }

                try {
                    hackCerts[0] = hackLeafCert();
                } catch (Exception e) {
                    Log.e(TAG, "ERROR creating hacked leaf certificate: " + e);
                }

                param.setResult(hackCerts);
            }
        });
    }
}
