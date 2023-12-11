package es.chiteroman.bootloaderspoofer;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.lang.reflect.Method;
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

            ASN1Sequence teeEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(7).toASN1Primitive();

            ASN1Sequence rootOfTrustAuthList = null;

            for (ASN1Encodable encodable : teeEnforcedAuthList) {
                if (!(encodable instanceof ASN1TaggedObject asn1TaggedObject)) continue;

                if (asn1TaggedObject.getTagNo() != 704) continue;

                rootOfTrustAuthList = (ASN1Sequence) asn1TaggedObject.getBaseObject().toASN1Primitive();

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

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            return converter.getCertificate(modCert);

        } catch (Exception e) {
            XposedBridge.log("ERROR in creating certificate: " + e);
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

                    for (Method declaredMethod : certificates[0].getClass().getDeclaredMethods()) {
                        if (declaredMethod.getName().toLowerCase(Locale.ROOT).contains("verify")) {
                            XposedBridge.hookMethod(declaredMethod, XC_MethodReplacement.DO_NOTHING);
                        }
                    }

                    certificates[0] = doLogic(certificates[0]);

                    param.setResult(certificates);
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }
    }
}
