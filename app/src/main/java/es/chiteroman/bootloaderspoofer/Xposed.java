package es.chiteroman.bootloaderspoofer;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
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
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {

    private static final KeyPair EC_KEYPAIR;
    private static final X509CertificateHolder holder_cert_1, holder_cert_2, holder_cert_3;
    private static ASN1Sequence swEnforcedAuthList, teeEnforcedAuthList;

    static {
        try {
            PEMParser parser = new PEMParser(new StringReader(Data.EC_PRIVATE_KEY));
            Object o = parser.readObject();
            parser.close();

            PEMKeyPair pemKeyPair = (PEMKeyPair) o;

            EC_KEYPAIR = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);

            PemReader reader_cert_1 = new PemReader(new StringReader(Data.CERT_1));
            PemObject pemObject = reader_cert_1.readPemObject();
            parser.close();

            holder_cert_1 = new X509CertificateHolder(pemObject.getContent());

            PemReader reader_cert_2 = new PemReader(new StringReader(Data.CERT_2));
            pemObject = reader_cert_2.readPemObject();
            parser.close();

            holder_cert_2 = new X509CertificateHolder(pemObject.getContent());

            PemReader reader_cert_3 = new PemReader(new StringReader(Data.CERT_3));
            pemObject = reader_cert_3.readPemObject();
            parser.close();

            holder_cert_3 = new X509CertificateHolder(pemObject.getContent());

        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static List<Certificate> getOtherCertList() throws Throwable {
        List<Certificate> certificates = new ArrayList<>();

        var c1 = new JcaX509v3CertificateBuilder(
                holder_cert_1.getSubject(),
                holder_cert_1.getSerialNumber(),
                holder_cert_1.getNotBefore(),
                holder_cert_1.getNotAfter(),
                holder_cert_1.getSubject(),
                EC_KEYPAIR.getPublic()
        );

        var c2 = new JcaX509v3CertificateBuilder(
                holder_cert_2.getSubject(),
                holder_cert_2.getSerialNumber(),
                holder_cert_2.getNotBefore(),
                holder_cert_2.getNotAfter(),
                holder_cert_2.getSubject(),
                EC_KEYPAIR.getPublic()
        );

        var c3 = new JcaX509v3CertificateBuilder(
                holder_cert_3.getSubject(),
                holder_cert_3.getSerialNumber(),
                holder_cert_3.getNotBefore(),
                holder_cert_3.getNotAfter(),
                holder_cert_3.getSubject(),
                EC_KEYPAIR.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(EC_KEYPAIR.getPrivate());

        X509CertificateHolder holder1 = c1.build(contentSigner);
        X509CertificateHolder holder2 = c2.build(contentSigner);
        X509CertificateHolder holder3 = c3.build(contentSigner);

        certificates.add(new JcaX509CertificateConverter().getCertificate(holder1));
        certificates.add(new JcaX509CertificateConverter().getCertificate(holder2));
        certificates.add(new JcaX509CertificateConverter().getCertificate(holder3));

        return certificates;
    }

    private static ASN1Primitive getEncodableFromList(int tagNo) {

        for (ASN1Encodable asn1Encodable : teeEnforcedAuthList) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;

            if (taggedObject.getTagNo() == tagNo) {
                return taggedObject.getBaseObject().toASN1Primitive();
            }
        }

        XposedBridge.log("Couldn't found " + tagNo + " object in TEE list");

        for (ASN1Encodable asn1Encodable : swEnforcedAuthList) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;

            if (taggedObject.getTagNo() == tagNo) {
                return taggedObject.getBaseObject().toASN1Primitive();
            }
        }

        XposedBridge.log("Couldn't found " + tagNo + " object in SW list");

        return null;
    }

    private static Extension addHackedExtension(ASN1Sequence keyDescription) {
        try {
            swEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(6).toASN1Primitive();
            teeEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(7).toASN1Primitive();

            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            SecureRandom secureRandom = new SecureRandom();

            secureRandom.nextBytes(bytes1);
            secureRandom.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {
                    new DEROctetString(bytes1),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(bytes2)
            };

            ASN1Sequence rootOfTrustSeq = new DLSequence(rootOfTrustEncodables);

            var Apurpose = getEncodableFromList(1);
            var Aalgorithm = getEncodableFromList(2);
            var AkeySize = getEncodableFromList(3);
            var AecCurve = getEncodableFromList(10);
            var AnoAuthRequired = getEncodableFromList(503);
            var AcreationDateTime = getEncodableFromList(701);
            var Aorigin = getEncodableFromList(702);
            var AosVersion = getEncodableFromList(705);
            var AosPatchLevel = getEncodableFromList(706);
            var AattestationApplicationId = getEncodableFromList(709);
            var AvendorPatchLevel = getEncodableFromList(718);
            var AbootPatchLevel = getEncodableFromList(719);

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
            var attestationApplicationId = new DLTaggedObject(true, 709, AattestationApplicationId);
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
                    attestationApplicationId,
                    vendorPatchLevel,
                    bootPatchLevel
            };

            ASN1Integer attestationVersion = new ASN1Integer(4);
            ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(2);
            ASN1Integer keymasterVersion = new ASN1Integer(41);
            ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(2);
            ASN1OctetString attestationChallenge = (ASN1OctetString) keyDescription.getObjectAt(4).toASN1Primitive();
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

        certBuilder.addExtension(addHackedExtension(keyDescription));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(EC_KEYPAIR.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Certificate[] certificates = (Certificate[]) param.getResultOrThrowable();

                        Certificate leaf = certificates[0];

                        if (!(leaf instanceof X509Certificate x509Certificate)) return;

                        byte[] bytes = x509Certificate.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");

                        if (bytes == null || bytes.length == 0) {
                            XposedBridge.log("Leaf certificate doesn't contain attestation extensions... Ignoring it.");
                            return;
                        }

                        List<Certificate> otherCerts = getOtherCertList();

                        Certificate[] hackCerts = new Certificate[4];

                        hackCerts[0] = hackLeafCert(x509Certificate);

                        hackCerts[1] = otherCerts.get(0);
                        hackCerts[2] = otherCerts.get(1);
                        hackCerts[3] = otherCerts.get(2);

                        param.setResult(hackCerts);

                    } catch (Throwable t) {
                        XposedBridge.log("ERROR: " + t);
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }
    }
}
