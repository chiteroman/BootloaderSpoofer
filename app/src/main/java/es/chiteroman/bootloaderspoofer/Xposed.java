package es.chiteroman.bootloaderspoofer;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.spongycastle.asn1.ASN1Boolean;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Enumerated;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {
    private static final Map<KeyPair, Certificate[]> map = new HashMap<>();
    private static byte[] attestationChallengeBytes = new byte[1];
    private static KeyPair keyPair;

    static {
        int numberOfCerts = 0;

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(Keybox.XML.getBytes()));

            NodeList keyList = document.getElementsByTagName("Key");

            for (int i = 0; i < keyList.getLength(); i++) {
                Node keyNode = keyList.item(i);
                if (keyNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element keyElement = (Element) keyNode;

                    String privateKeyPEM = keyElement.getElementsByTagName("PrivateKey").item(0).getTextContent();
                    KeyPair keyPair = parseKeyPair(privateKeyPEM);

                    NodeList certificateNodes = keyElement.getElementsByTagName("Certificate");

                    int certs = certificateNodes.getLength();

                    Certificate[] certificates = new Certificate[certs];

                    for (int j = 0; j < certs; j++) {
                        String certificatePEM = certificateNodes.item(j).getTextContent();
                        Certificate certificate = parseCert(certificatePEM);
                        certificates[j] = certificate;
                    }

                    map.put(keyPair, certificates);

                    numberOfCerts += certs;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        XposedBridge.log("[BootloaderSpoofer] Loaded " + map.size() + " keys!");
        XposedBridge.log("[BootloaderSpoofer] Loaded " + numberOfCerts + " certificates!");
    }

    private static KeyPair parseKeyPair(String key) throws Exception {
        Object object;
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            object = parser.readObject();
        }

        PEMKeyPair pemKeyPair = (PEMKeyPair) object;

        return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    }

    private static Certificate parseCert(String cert) throws Exception {
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }

        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());

        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static Extension addHackedExtension() {
        try {
            SecureRandom random = new SecureRandom();

            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            random.nextBytes(bytes1);
            random.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(bytes1), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(bytes2)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            ASN1Integer[] purposesArray = {new ASN1Integer(2), new ASN1Integer(3)};

            ASN1Encodable[] digests = {new ASN1Integer(4)};

            var Apurpose = new DERSet(purposesArray);
            var Aalgorithm = new ASN1Integer(3);
            var AkeySize = new ASN1Integer(256);
            var Adigest = new DERSet(digests);
            var AecCurve = new ASN1Integer(1);
            var AnoAuthRequired = DERNull.INSTANCE;
            var AosVersion = new ASN1Integer(140000);
            var AosPatchLevel = new ASN1Integer(202312);

            var AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            var Aorigin = new ASN1Integer(0);

            var purpose = new DERTaggedObject(true, 1, Apurpose);
            var algorithm = new DERTaggedObject(true, 2, Aalgorithm);
            var keySize = new DERTaggedObject(true, 3, AkeySize);
            var digest = new DERTaggedObject(true, 5, Adigest);
            var ecCurve = new DERTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DERTaggedObject(true, 503, AnoAuthRequired);
            var creationDateTime = new DERTaggedObject(true, 701, AcreationDateTime);
            var origin = new DERTaggedObject(true, 702, Aorigin);
            var rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DERTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DERTaggedObject(true, 706, AosPatchLevel);

            ASN1Encodable[] teeEnforcedEncodables = {purpose, algorithm, keySize, digest, ecCurve, noAuthRequired, creationDateTime, origin, rootOfTrust, osVersion, osPatchLevel};

            ASN1Integer attestationVersion = new ASN1Integer(200);
            ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(2);
            ASN1Integer keymasterVersion = new ASN1Integer(200);
            ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(2);
            ASN1OctetString attestationChallenge = new DEROctetString(attestationChallengeBytes);
            ASN1OctetString uniqueId = new DEROctetString("".getBytes());
            ASN1Sequence softwareEnforced = new DERSequence();
            ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

            ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

            ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

            ASN1OctetString keyDescriptionOctetStr = new DEROctetString(keyDescriptionHackSeq);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);

        } catch (Exception e) {
            XposedBridge.log("[BootloaderSpoofer] Error create extensions: " + e);
        }

        return null;
    }

    private static Certificate hackLeafCert() throws Exception {

        SecureRandom random = new SecureRandom();

        var certBuilder = new JcaX509v3CertificateBuilder(new X500Name("CN=chiteroman"), new BigInteger(128, random), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000), new X500Name("CN=Android Keystore Key"), keyPair.getPublic());

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

        certBuilder.addExtension(addHackedExtension());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {

        for (KeyPair pair : map.keySet()) {
            if (KeyProperties.KEY_ALGORITHM_EC.equals(pair.getPrivate().getAlgorithm())) {
                keyPair = pair;
            }
        }

        Class<?> AndroidKeyStoreKeyPairGeneratorSpi = XposedHelpers.findClassIfExists("android.security.keystore2.AndroidKeyStoreKeyPairGeneratorSpi", lpparam.classLoader);

        if (AndroidKeyStoreKeyPairGeneratorSpi == null) {

            KeyPairGeneratorSpi keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyGenerator.getClass(), "generateKeyPair", XC_MethodReplacement.returnConstant(keyPair));

        } else {

            XposedHelpers.findAndHookMethod(AndroidKeyStoreKeyPairGeneratorSpi, "generateKeyPair", XC_MethodReplacement.returnConstant(keyPair));
        }

        XposedHelpers.findAndHookMethod(KeyGenParameterSpec.Builder.class, "setAttestationChallenge", byte[].class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                attestationChallengeBytes = (byte[]) param.args[0];
            }
        });

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    LinkedList<Certificate> certificates = new LinkedList<>(Arrays.asList(map.get(keyPair)));

                    try {
                        certificates.addFirst(hackLeafCert());
                    } catch (Exception e) {
                        XposedBridge.log("[BootloaderSpoofer] ERROR creating hacked leaf certificate: " + e);
                    }

                    return certificates.toArray(new Certificate[0]);
                }
            });
        } catch (KeyStoreException e) {
            XposedBridge.log("[BootloaderSpoofer] ERROR: " + e);
        }
    }
}
