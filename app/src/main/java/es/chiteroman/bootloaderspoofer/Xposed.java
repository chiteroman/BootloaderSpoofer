package es.chiteroman.bootloaderspoofer;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {
    private static final SecureRandom random = new SecureRandom();
    private static final Deque<Certificate> EC_CERTS = new ArrayDeque<>(3);
    private static final Deque<Certificate> RSA_CERTS = new ArrayDeque<>(3);
    private static byte[] attestationChallengeBytes = new byte[0];
    private static KeyPair EC_KEYPAIR, RSA_KEYPAIR;
    private static String MODULE_PATH;

    private static void loadKeyBox() {
        try {
            EC_CERTS.clear();
            RSA_CERTS.clear();

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

            Document doc = dBuilder.parse(new ByteArrayInputStream(KEYBOX.getBytes(StandardCharsets.UTF_8)));
            doc.getDocumentElement().normalize();

            Element rootElement = doc.getDocumentElement();

            int numberOfKeyboxes = Integer.parseInt(rootElement.getElementsByTagName("NumberOfKeyboxes").item(0).getTextContent());
            XposedBridge.log("Number of Keyboxes: " + numberOfKeyboxes);

            NodeList keyboxList = rootElement.getElementsByTagName("Keybox");
            for (int i = 0; i < keyboxList.getLength(); i++) {
                Node keyboxNode = keyboxList.item(i);
                if (keyboxNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element keyboxElement = (Element) keyboxNode;
                    String deviceId = keyboxElement.getAttribute("DeviceID");
                    XposedBridge.log("Device ID: " + deviceId);

                    NodeList keyList = keyboxElement.getElementsByTagName("Key");
                    for (int j = 0; j < keyList.getLength(); j++) {
                        Node keyNode = keyList.item(j);
                        if (keyNode.getNodeType() == Node.ELEMENT_NODE) {
                            Element keyElement = (Element) keyNode;

                            String algorithm = keyElement.getAttribute("algorithm");

                            Element privateKeyElement = (Element) keyElement.getElementsByTagName("PrivateKey").item(0);
                            String privateKey = privateKeyElement.getTextContent();

                            if ("ecdsa".equals(algorithm)) EC_KEYPAIR = parsePrivateKey(privateKey);
                            else if ("rsa".equals(algorithm))
                                RSA_KEYPAIR = parsePrivateKey(privateKey);

                            NodeList certList = keyElement.getElementsByTagName("Certificate");
                            for (int k = 0; k < certList.getLength(); k++) {
                                Node certNode = certList.item(k);
                                if (certNode.getNodeType() == Node.ELEMENT_NODE) {
                                    Element certElement = (Element) certNode;
                                    String certValue = certElement.getTextContent();

                                    if ("ecdsa".equals(algorithm))
                                        EC_CERTS.add(parseCert(certValue));
                                    else if ("rsa".equals(algorithm))
                                        RSA_CERTS.add(parseCert(certValue));
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            XposedBridge.log("[BootloaderSpoofer] ERROR: " + e);
            throw new RuntimeException();
        }
    }

    private static KeyPair parsePrivateKey(String key) throws IOException {
        key = key.trim();

        PEMParser parser = new PEMParser(new StringReader(key));
        Object o = parser.readObject();
        parser.close();

        PEMKeyPair pemKeyPair = (PEMKeyPair) o;

        return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    }

    private static Certificate parseCert(String cert) throws IOException, CertificateException {
        cert = cert.trim();

        PEMParser parser = new PEMParser(new StringReader(cert));
        Object o = parser.readObject();
        parser.close();

        X509CertificateHolder holder = (X509CertificateHolder) o;

        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static Extension addHackedExtension() {
        try {
            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            random.nextBytes(bytes1);
            random.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(bytes1), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(bytes2)};

            ASN1Sequence rootOfTrustSeq = new DLSequence(rootOfTrustEncodables);

            ASN1Integer[] purposesArray = {new ASN1Integer(2), new ASN1Integer(3)};

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

            ASN1Encodable[] teeEnforcedEncodables = {purpose, algorithm, keySize, ecCurve, noAuthRequired, creationDateTime, origin, rootOfTrust, osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel};

            ASN1Integer attestationVersion = new ASN1Integer(4);
            ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(2);
            ASN1Integer keymasterVersion = new ASN1Integer(41);
            ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(2);
            ASN1OctetString attestationChallenge = new DEROctetString(attestationChallengeBytes);
            ASN1OctetString uniqueId = new DEROctetString("".getBytes());
            ASN1Sequence softwareEnforced = new DLSequence();
            ASN1Sequence teeEnforced = new DLSequence(teeEnforcedEncodables);

            ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

            ASN1Sequence keyDescriptionHackSeq = new DLSequence(keyDescriptionEncodables);

            ASN1OctetString keyDescriptionOctetStr = new DEROctetString(keyDescriptionHackSeq);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), true, keyDescriptionOctetStr);

        } catch (Exception e) {
            XposedBridge.log("[BootloaderSpoofer] Error create extensions: " + e);
        }

        return null;
    }

    private static Certificate hackLeafCert() throws Exception {

        var certBuilder = new JcaX509v3CertificateBuilder(new X500Name("CN=chiteroman"), new BigInteger(128, random), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000), new X500Name("CN=Android Keystore Key"), RSA_KEYPAIR.getPublic());

        certBuilder.addExtension(addHackedExtension());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(RSA_KEYPAIR.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {

        loadKeyBox();

        Class<?> AndroidKeyStoreKeyPairGeneratorSpi = XposedHelpers.findClassIfExists("android.security.keystore2.AndroidKeyStoreKeyPairGeneratorSpi", lpparam.classLoader);
        XposedHelpers.findAndHookMethod(AndroidKeyStoreKeyPairGeneratorSpi, "generateKeyPair", XC_MethodReplacement.returnConstant(RSA_KEYPAIR));

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGenerator.getClass(), "generateKeyPair", XC_MethodReplacement.returnConstant(RSA_KEYPAIR));

            keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGenerator.getClass(), "generateKeyPair", XC_MethodReplacement.returnConstant(RSA_KEYPAIR));

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {

            XposedBridge.log("[BootloaderSpoofer] ERROR: " + e);
        }

        Class<?> Builder = XposedHelpers.findClass(KeyGenParameterSpec.Builder.class.getName(), lpparam.classLoader);
        XposedHelpers.findAndHookMethod(Builder, "setAttestationChallenge", byte[].class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(XC_MethodHook.MethodHookParam param) {
                attestationChallengeBytes = (byte[]) param.args[0];
                XposedBridge.log("[BootloaderSpoofer] attestationChallenge: " + Arrays.toString(attestationChallengeBytes));
            }
        });

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    Deque<Certificate> certificates = new ArrayDeque<>(RSA_CERTS);

                    try {
                        certificates.addFirst(hackLeafCert());
                    } catch (Exception e) {
                        XposedBridge.log("[BootloaderSpoofer] ERROR creating hacked leaf certificate: " + e);
                    }

                    return certificates.toArray(new Certificate[0]);
                }
            });
        } catch (CertificateException | KeyStoreException | IOException |
                 NoSuchAlgorithmException e) {

            XposedBridge.log("[BootloaderSpoofer] ERROR: " + e);
        }
    }

    private static final String KEYBOX = """
            <?xml version="1.0"?>
            <AndroidAttestation>
            <NumberOfKeyboxes>1</NumberOfKeyboxes>
            <Keybox DeviceID="NUBIA_NX606J_AK_0000001"><Key algorithm="ecdsa"><PrivateKey format="pem">
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEINHUR+pr+/0UCLbjPYQq/2bw6JekJvor38TVlVAUMP5uoAoGCCqGSM49
            AwEHoUQDQgAE8QKCOumQkEdLnqps1h6aYQM/O4VREnhHF0tJ3pcQ0cfQS5WgnhzP
            OD5vloDit6xBGoUXs+QqtMEflqYClhCL/Q==
            -----END EC PRIVATE KEY-----
            </PrivateKey><CertificateChain><NumberOfCertificates>3</NumberOfCertificates><Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            MIICKzCCAbKgAwIBAgIKAndWeGYmQ2cZQTAKBggqhkjOPQQDAjAbMRkwFwYDVQQF
            ExA1YjAzNTljY2E4ODc5Y2I1MB4XDTE2MDUyNjE2NTczNVoXDTI2MDUyNDE2NTcz
            NVowGzEZMBcGA1UEBRMQMzQ0NjZhZWI2Nzc3NmMyNzBZMBMGByqGSM49AgEGCCqG
            SM49AwEHA0IABPECgjrpkJBHS56qbNYemmEDPzuFURJ4RxdLSd6XENHH0EuVoJ4c
            zzg+b5aA4resQRqFF7PkKrTBH5amApYQi/2jgd0wgdowHQYDVR0OBBYEFN3jZFzm
            lLhaMqADvRaisWt1mMOFMB8GA1UdIwQYMBaAFAbd7gqSHZtx4caJQUTvOTlwJgA1
            MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMCQGA1UdHgQdMBugGTAXghVp
            bnZhbGlkO2VtYWlsOmludmFsaWQwVAYDVR0fBE0wSzBJoEegRYZDaHR0cHM6Ly9h
            bmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wMjc3NTY3ODY2
            MjY0MzY3MTk0MTAKBggqhkjOPQQDAgNnADBkAjAThg70bAjRwWEffDdAV7aarwB6
            mw4ccMG/0apN4/Bb6Jz4wyXUj4DxhtcTOIvVfrICMEiDdyXEsZZl8yrOGs6Z6XWJ
            Fd3EdZ5vLcC1+ZdSNNveJfW1u0+iP1WaDktKfTjvNw==
            -----END CERTIFICATE-----
            </Certificate><Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            MIIDwzCCAaugAwIBAgIKA4gmZ2BliZaFczANBgkqhkiG9w0BAQsFADAbMRkwFwYD
            VQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE2MDUyNjE2NDEyOVoXDTI2MDUyNDE2
            NDEyOVowGzEZMBcGA1UEBRMQNWIwMzU5Y2NhODg3OWNiNTB2MBAGByqGSM49AgEG
            BSuBBAAiA2IABHf4FUKTZivDuwdyVbXyPF12IRuDzZKq61MbqooE3/gx9gIS9pFS
            4NZgGTnjSMm6ltYrCv3sDzuPQls+V+BLPQgNfRHavmP9eulc1uR3GNgCnKqxB2o0
            QcTQGPAxJA81c6OBtjCBszAdBgNVHQ4EFgQUBt3uCpIdm3HhxolBRO85OXAmADUw
            HwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB
            /zAOBgNVHQ8BAf8EBAMCAYYwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cHM6Ly9hbmRy
            b2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC9FOEZBMTk2MzE0RDJG
            QTE4MA0GCSqGSIb3DQEBCwUAA4ICAQAsPFNbAeVGRXKg0H1Ixy31n+vc1GAtLTtd
            ruQGZ3rk6Dq3G5OiNfwLI4vRowDERgTr5RoVRMLs9HzTTCvvdEBhcILKOnaPAd6J
            g4HvBi8hsfbXEvRi2kmIfiYAabC71ErJLFEMprTJMSDEOe3lXCJG409z99ofsf/s
            1M1i77NFVCwstAvRLMjc9TjxRXrGrGD0rMdG2RkionXa3H+4cYqSUf7JCIW6dMB2
            p+4R3n463DqxxSJNGbchGGUbL6b0qIWdaVcwG2ro+WyItfyw5C4h9XSosauyC9aj
            jZLt8RAK2ouZHN/kyIXcD1U7IFbSy0SZfaRDLNCzse4iL6IOnuyITEFLnvLfcDSw
            NX1/ptBRAeeme7G1nwpeohJjiddmf20e421+n3tWUyUhLk9s83MJQQp+mhfApA1Q
            vz+a7M3OqPvHhBoeu6C4NOlYkb8mrjtuZ/RU5WIRXfyXZqA05Qnu8usuxxNFozU5
            hWbXIZQx7at2x/7t8/kgHSJhKs4hWIdbVgIDyWIhgoDD+gqTIRlzTwrS876dgy0M
            TZm1riMEBB5jvAhaeciDBf8u6AFWnMsS0UVtOinr5lTRkHSwie2n90kazqpkeMUd
            nbBSG7HSMhyg5lvem9G82NakH4S1EPgRBLN1eF8Q51ZmzeNl3DnIGGjNI+LAXw10
            KVuEkzgd8A==
            -----END CERTIFICATE-----
            </Certificate><Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            </Certificate></CertificateChain></Key><Key algorithm="rsa"><PrivateKey format="pem">
            -----BEGIN RSA PRIVATE KEY-----
            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
            -----END RSA PRIVATE KEY-----
            </PrivateKey><CertificateChain><NumberOfCertificates>3</NumberOfCertificates><Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            7qaZlBkmipuwCn9r
            -----END CERTIFICATE-----
            </Certificate><Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            yhC5FAE=
            -----END CERTIFICATE-----
            </Certificate><Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            </Certificate></CertificateChain></Key></Keybox>
            </AndroidAttestation>""";
}
