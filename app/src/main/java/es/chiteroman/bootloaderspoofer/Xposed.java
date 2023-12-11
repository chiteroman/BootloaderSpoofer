package es.chiteroman.bootloaderspoofer;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.StringReader;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Locale;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {
    private static final String SW_RSA_ATTEST_ROOT_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXQIBAAKBgQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAsQ+wz
            fNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4RFlXYfC78hdLt0GA
            ZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwIDAQAB
            AoGAU8dxXchmqzVNbbvff7zgUa63YErk51Yem/EXzhkMaIXRkMO0edaCtZtnkRvg
            9OQ2qEiLWaCTlUoyU7H/HUn2lwTQsOXyZI7dHijVDRMIv1mmrHCrGW/JC8FXfPLS
            r3L3KoHXQVYL2mslbR8Rpogxq4WwnwK6XqSTH9mynFwQwEkCQQDMX3EZk3ricWVH
            ruXD0BpXOMMpZuLu4rg5+1L51WEJvItIMeSjLuNa+g3AI8AYTYYi/aSLk6XEv82L
            iXFGmJ2XAkEAy3M8k8Z0QzHae4olduqoHVWEarBtDE+fqFQBWgdm8fZhdHWrvlAc
            qwJIXMUVc+dWm/FAQarCjbqWqhCRdaYgnQJBAJ7z7GdUCVNtlrQ2F4ZAqPwFreTZ
            nM7njxmpm1Os3hhQiJPSGl3A7huoOGGkbJd6VEWKuRvF7jwkYZ2RfITH1mkCQAvh
            X9E1Toa5+4spRwTJsSV9X+0m/kcwwx7+QNH0CrPockptsKi9Xt8xk+4u6BDLmogi
            r2DmStQh6DhoHUZkfBUCQQCOgBkqH/15drpdR+BQH3VaP4/ALFfxR9E3G+lS+M5a
            IqJEk9kh8vjuGzTaAZyU5keUmpWNc1gI7OvDMaH4+8vQ
            -----END RSA PRIVATE KEY-----
            """;
    private static volatile boolean hardwareAttesatation = true;

    private static int indexOf(byte[] array, byte[] target) {
        outer:
        for (int i = 0; i < array.length - target.length + 1; i++) {
            for (int j = 0; j < target.length; j++) {
                if (array[i + j] != target[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static Certificate doLogic(Certificate certificate) {
        try {
            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());

            Extension extension = certificateHolder.getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"));

            ASN1Sequence keyDescription = ASN1Sequence.getInstance(extension.getExtnValue().getOctets());

            ASN1Sequence swEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(6).toASN1Primitive();

            ASN1Sequence teeEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(7).toASN1Primitive();

            ASN1Sequence rootOfTrustAuthList = null;

            for (ASN1Encodable encodable : swEnforcedAuthList) {
                if (!(encodable instanceof ASN1TaggedObject asn1TaggedObject)) continue;

                if (asn1TaggedObject.getTagNo() != 704) continue;

                rootOfTrustAuthList = (ASN1Sequence) asn1TaggedObject.getBaseObject().toASN1Primitive();

                hardwareAttesatation = false;

                break;
            }

            for (ASN1Encodable encodable : teeEnforcedAuthList) {
                if (!(encodable instanceof ASN1TaggedObject asn1TaggedObject)) continue;

                if (asn1TaggedObject.getTagNo() != 704) continue;

                rootOfTrustAuthList = (ASN1Sequence) asn1TaggedObject.getBaseObject().toASN1Primitive();

                hardwareAttesatation = true;

                break;
            }

            if (rootOfTrustAuthList == null) {
                throw new CertificateException("ERROR, Root of Trust is null");
            }

            byte[] bytes = certificate.getEncoded();

            int index = indexOf(bytes, rootOfTrustAuthList.getEncoded());

            bytes[index + 38] = 1;
            bytes[index + 41] = 0;

            X509CertificateHolder modCert = new X509CertificateHolder(bytes);

            if (hardwareAttesatation) {

                JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

                return converter.getCertificate(modCert);

            } else {

                PEMParser parser = new PEMParser(new StringReader(SW_RSA_ATTEST_ROOT_KEY));
                PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
                parser.close();

                JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();

                KeyPair keyPair = jcaPEMKeyConverter.getKeyPair(pemKeyPair);

                X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(certificateHolder.getSubject(), certificateHolder.getSerialNumber(), certificateHolder.getNotBefore(), certificateHolder.getNotAfter(), certificateHolder.getSubject(), keyPair.getPublic());

                certBuilder.copyAndAddExtension(extension.getExtnId(), extension.isCritical(), modCert);

                ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());

                X509CertificateHolder certHolder = certBuilder.build(contentSigner);

                return new JcaX509CertificateConverter().getCertificate(certHolder);
            }

        } catch (Exception e) {
            XposedBridge.log("ERROR creating certificate: " + e);
        }

        return certificate;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Certificate[] certificates = (Certificate[]) param.getResult();

                    certificates[0] = doLogic(certificates[0]);

                    if (hardwareAttesatation) {
                        for (Method method : certificates[0].getClass().getMethods()) {
                            if (method.getName().toLowerCase(Locale.ROOT).contains("verify")) {
                                XposedBridge.hookMethod(method, XC_MethodReplacement.DO_NOTHING);
                            }
                        }
                    }

                    param.setResult(certificates);
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }
    }
}
