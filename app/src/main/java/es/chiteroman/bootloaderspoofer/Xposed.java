package es.chiteroman.bootloaderspoofer;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Xposed implements IXposedHookLoadPackage {
    private static int indexOf(byte[] array) {
        final byte[] PATTERN = {48, 74, 4, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 10, 1, 2};
        outer:
        for (int i = 0; i < array.length - PATTERN.length + 1; i++) {
            for (int j = 0; j < PATTERN.length; j++) {
                if (array[i + j] != PATTERN[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Certificate[] certificates = (Certificate[]) param.getResultOrThrowable();
                    if (certificates[0] instanceof X509Certificate cert) {

                        for (Method method : cert.getClass().getMethods()) {
                            if (method.getName().toLowerCase(Locale.ROOT).contains("verify")) {
                                XposedBridge.hookMethod(method, XC_MethodReplacement.DO_NOTHING);
                            }
                        }

                        byte[] bytes = cert.getEncoded();
                        if (bytes == null || bytes.length == 0) return;
                        int index = indexOf(bytes);
                        if (index == -1) return;
                        bytes[index + 38] = 1;
                        bytes[index + 41] = 0;
                        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                        X509Certificate modCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));
                        certificates[0] = modCert;
                        param.setResult(certificates);
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }
    }
}
