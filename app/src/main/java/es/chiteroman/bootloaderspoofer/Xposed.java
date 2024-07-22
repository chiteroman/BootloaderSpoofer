package es.chiteroman.bootloaderspoofer;

import android.app.AndroidAppHelper;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
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
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class Xposed implements IXposedHookLoadPackage {
    private static final KeyPair keyPair_EC, keyPair_RSA;
    private static final LinkedList<Certificate> certs_EC = new LinkedList<>();
    private static final LinkedList<Certificate> certs_RSA = new LinkedList<>();
    private static byte[] attestationChallengeBytes = new byte[1];

    static {
        try {

            String str = """
                    -----BEGIN EC PRIVATE KEY-----
                    MHcCAQEEIITtDeCxHmadsR64nZgJmqW/tuWN2vjvpKHQc+ZK16vCoAoGCCqGSM49
                    AwEHoUQDQgAEze1OfhlNmrrghv23VH1080nuiOHTkE6U6UafCefyO9AeJb3ZjzTr
                    jJ5sVXRQ8zoP0kea8mB2Cg2/acuzQIcJeg==
                    -----END EC PRIVATE KEY-----""";

            keyPair_EC = parseKeyPair(str);

            str = """
                    -----BEGIN RSA PRIVATE KEY-----
                    MIIG5AIBAAKCAYEApPn7neF2UhbrkP/3IPA3H/zvQa7rXolMXecK0jKqb6dnRqgQ
                    u0cZajVvaSrYABTFDVfuCX5IEMiM4gYsOT7HDVY0h/SIL0OrdvXR+SHmLRc8D/rK
                    T9eQIIUtgf776aI/zc2EqPXRO3P8UahDDKfxWClUUOSfcv56zyKaWBaTsOgLGIE8
                    SiC5seRRd1Bo7qh3UVyP3qVA8pX4AQAA9odg+kXtBA52LeLy5RHcaJJzMqKSPNF2
                    MFuJSCD3qU7BB5oBMmnYV3RUFa/+QcI/6tg7LVS/P/Elyqnmb2WnuCPhPEtaW7Ip
                    SR8Vdmku7YFE7zXiCrFolxFd0pgNjfuGFdoqUbjyWfrzt0SABgKTYRQygX7mquiZ
                    uKzE0d02gkB9ucG123aupjN07XQC5DqwDG+rBdqNQ6yNL49LACnxMSxwCGoh6dpc
                    9jgXzT1SMH9v0Wp+krIWd94/WG+HosFFpCXKEj0yAQvCVzkBfx3wfHS/scYY6yXK
                    UCTGqwUPIcQ7MdnHAgMBAAECggGBAIP0//F0mXNnqdw9IKpT+YO4iJb9Fn5zS4YA
                    e4NNy02rlMvLOjbR095EB20TO9o0wri9kEQ/odzqzOUtEspnEEf2n+XvDc7gTZHF
                    ZcHj/3wpjX0qmA/s1/drDs9f6Jcjk+1FacrLdCQdzcBy2c6RtlVSGYLqmy8bpZdw
                    kgvLYy6pK9bZ6CNSsbU8bn0E8CmUznthkiIABEcE9W23Vw3ZkxQcQkxwVM63LJlV
                    A/sQyNvDdTz4PZTIYrIyzGW7/GHcJ7glMJQnvPVIl4XZqhpxk/iK8KC6FqclnHG5
                    BA2EaDrXiHa+THqGavkPpLzIBIS3odxFEDiRbrekDVT7nVQ21OhSIg4Mp++CT/RL
                    uiavlXJC0qobL23GRm9IUmkq88pGt1K06V3csaKfgOnJn4EMV5HorARnq1Zhtw/P
                    4Pzse+BQkTRfANVQ4ueocQus+MtutsJESvh4MF+ghgf0xeLWQs7rHNEIbRZhVxyX
                    kAQngkmoBw2U/Gziz7gkcXgRlh6HgQKBwQDQTCALdpIS8uWZfV8UQK5WzqKIyX3+
                    /NhFExsHI3GBjRSMVPbtphSPuD54jTZKboLuOGfHJAWleduYr0XUiUkMku37Y7Xj
                    anGUzSZvB3qasKxHfWxZKH+1OBWFlj7bkwgsLAh4+50Md44d7MfceD0mWBOyVlRt
                    5L8vIzLPxltbRcidISlnk/Moqk38QVGtQ7vo3NOR6PJwPY/V/g1/QDC2LORBNmt9
                    6Eqs3LdNf+3rSCaaYhD1XbaYQ7j095eFIBcCgcEAysIUdEUXrySRGGQ2PiBlszD0
                    l9jqL/wJEe+tOTu3F7+Qu7zmcS5Q0cbFJY+ztPPgzSrw2DOiFvPH63KlA9wJ2POR
                    O2pXar668FxJjoNF1Jkb8vMISrk/IHDYn7GL+/XTPiB+RglVgjz2ID+Z9UQZZRDp
                    R8p0Eqa12OxoP7HK7fmUkBjWKTqi1VDtfB6vM+EM7cxd+CsiKpazDjWGwMMc0jz7
                    ABiMFhhKiC+yq4fECXHt6ZA9oh8VGUdp7AIJO/HRAoHBAJqJP+UBTRJ93tXna9js
                    u+tvVqrBQpchI5rrt8uuAhIphysuBhz+cJbIDKEHs1W5c64lbukR0paYN9Gph9dN
                    G0MW5zTxHwrf9/B7253YIKAPn2FSrkXfhBAA0gbQF0Z0aUXMTWTk1/ld4bRV7Vmm
                    Y0fFZKeU4QK/CRCBvrrj4PdwaIwbBEryOx7aaw1RsLUpYYo7+0NvXh7jrYkH+R+F
                    kh42ZAn1w/4fjvd8sQnwdaVvXCSByS8hHc0NwXUNE/8SdQKBwHfg3+8Omr42xILD
                    XT7GMNsNatAMtAnC3in4p1ZbdBlabdxSB32LgMVG3HEk0X9/Yb5sURHDFWa0o9MV
                    aXMqubfH6mpSqXS3aBeMuQDFpJfaHqg6AQENHcG0dp+UfctuwILO+1m1UxU5rdvL
                    Pt/Ab7NNmF+V16LfZkznGYvvNqgVFD1OMfEWdgfhXUgxbC0kNlyypCyCdCTyDNOt
                    2gpGUdgLreuUl97IZei3KtA36TQcZCnf2lDsR7E2g+3CFmuWwQKBwDucj8UH0GKr
                    WEEO7q/Z5Vz2e9EyRRXdgrv/yRW1qm7EKAyLPfIb2TKQZqi5Mwr8umnaOfSrqt2p
                    1Kklhtz5AT73hXaoOqiXmxYDQoWnlXprJekDuV3EbBS0UuhXHrtRmg4bUmZoyTNl
                    YufICOO52cpPA/K7a0kRbNvwWHwPhZb5GFu9R030YT2yVMDtPIGr5BjwQYrHbxJW
                    0b13VeIupduHFWNQjkEpkFGvXQT9B8AIFVjOLbfPZKxY/WUltEOFhQ==
                    -----END RSA PRIVATE KEY-----""";

            keyPair_RSA = parseKeyPair(str);

            str = """
                    -----BEGIN CERTIFICATE-----
                    MIIB8jCCAXmgAwIBAgIQFOOLOXnt7wbQ6VtxMaCLIjAKBggqhkjOPQQDAjA5MQww
                    CgYDVQQMDANURUUxKTAnBgNVBAUTIGUwYzM1NDhhNDdlNzNmMmE3NWZiOWVkNmRh
                    NWJmM2U4MB4XDTIwMDkyODIwMTgzOFoXDTMwMDkyNjIwMTgzOFowOTEMMAoGA1UE
                    DAwDVEVFMSkwJwYDVQQFEyAxOTllNWRjYWY1NjZhMGUzZWY5MDY2ZjMwNWU3NTZj
                    YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM3tTn4ZTZq64Ib9t1R9dPNJ7ojh
                    05BOlOlGnwnn8jvQHiW92Y8064yebFV0UPM6D9JHmvJgdgoNv2nLs0CHCXqjYzBh
                    MB0GA1UdDgQWBBRNOkkWmT0V3Uyj7ZjdQov5G6K66TAfBgNVHSMEGDAWgBTCUwGu
                    PmMBr/KlnNVfgJSOADJOPDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIC
                    BDAKBggqhkjOPQQDAgNnADBkAjAJKrzd5ePYC4kDP4xLvI8xuaBy1F3g4aeKWQNx
                    yFCFZMvuCwZ0vu58TDtoeGBsKVACMF7ixBjTVML8pHXcAh6cjk+60Syk0QsbnKxo
                    eDO28ev+S2qAjI1yvJD1UzqjyoIOCg==
                    -----END CERTIFICATE-----""";

            certs_EC.add(parseCert(str));

            str = """
                    -----BEGIN CERTIFICATE-----
                    MIIDkzCCAXugAwIBAgIQFk/xbbOK0z0ZBF99wwx/zDANBgkqhkiG9w0BAQsFADAb
                    MRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIwMDkyODIwMTc0OVoXDTMw
                    MDkyNjIwMTc0OVowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3
                    ZTczZjJhNzVmYjllZDZkYTViZjNlODB2MBAGByqGSM49AgEGBSuBBAAiA2IABJHz
                    0uU3kbaMjfVN38GXDgIBLl4Gp7P59n6+zmqoswoBrbrsCiFOWUU+B918FnEVcW86
                    joLS+Ysn7msakvrHanJMJ4vDwD7/p+F6nkQ9J95FEkuq71oGTzCrs6SlCHu5XqNj
                    MGEwHQYDVR0OBBYEFMJTAa4+YwGv8qWc1V+AlI4AMk48MB8GA1UdIwQYMBaAFDZh
                    4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
                    AgIEMA0GCSqGSIb3DQEBCwUAA4ICAQAnO5KNrbenSYxIOfzxH47CNi3Qz2O5+FoP
                    W7svNjggg/hZotSwbddpSVa+fdQYYYZdHMPNjQKXYaDxPPC2i/8KBhscq+TW1k9Y
                    KP+qNGMZ2CKzRIT0pByL0M5LQNbH6VxAvzGlaCvTOIsDmlLyjzmT9QMtjWkmLKdu
                    ISOa72hGMM4kCcIRKcgsq/s00whsOJ6IT27lp85AATuL9NvNE+kC1TZ96zEsR8Op
                    lur4euBmFoGzmtSFsZa9TNyc68RuJ+n/bY7iI77wXUz7ER6uj/sfnrjYJFclLjIj
                    m8Mqp69IZ1nbJsKTgg0e5X4xeecNPLSMp/hGqDOvNnSVbpri6Djm0ZWILk65BeRx
                    ANDUhICg/iuXnbSLIgPAIxsmniTV41nnIQ2nwDxVtfStsPzSWeEKkMTeta+Lu8jK
                    KVDcRTt2zoGx+JOQWaEWpOTUM/xZwnJamdHsKBWsskQhFMxLIPJbMeYAeCCswDTE
                    +LQv31wDTxSrFVw/fcfVY6PSRZWoy+6Q/zF3JATwQnYxNUchZG4suuy/ONPbOhD0
                    VdzjkSyza6fomTw2F1G3c4jSQIiNV3OIxsxh4ja1ssJqMPuQzRcGGXxX8yQHrg+t
                    +Dxn32jFVhl5bxTeKuI6mWBYM+/qEBTBEXLNSmVdxrntFaPmiQcguBSFR1oHZyi/
                    xS/jbYFZEQ==
                    -----END CERTIFICATE-----""";

            certs_EC.add(parseCert(str));

            str = """
                    -----BEGIN CERTIFICATE-----
                    MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
                    BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAz
                    NzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
                    AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
                    Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
                    tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
                    nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
                    C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
                    oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
                    JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
                    sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
                    igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
                    RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
                    aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
                    AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
                    IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
                    VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnu
                    XKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
                    h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cno
                    L/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2ok
                    QBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
                    D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAI
                    mMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoW
                    Fua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
                    oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09o
                    jm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUB
                    ZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
                    ex0SdDrx+tWUDqG8At2JHA==
                    -----END CERTIFICATE-----""";

            certs_EC.add(parseCert(str));

            str = """
                    -----BEGIN CERTIFICATE-----
                    MIIE4DCCAsigAwIBAgIRAMInLPJfnMrFtWM6NrXgj6kwDQYJKoZIhvcNAQELBQAw
                    OTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3ZTczZjJhNzVmYjll
                    ZDZkYTViZjNlODAeFw0yMDA5MjgyMDE4MzhaFw0zMDA5MjYyMDE4MzhaMDkxDDAK
                    BgNVBAwMA1RFRTEpMCcGA1UEBRMgMTk5ZTVkY2FmNTY2YTBlM2VmOTA2NmYzMDVl
                    NzU2Y2EwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCk+fud4XZSFuuQ
                    //cg8Dcf/O9BruteiUxd5wrSMqpvp2dGqBC7RxlqNW9pKtgAFMUNV+4JfkgQyIzi
                    Biw5PscNVjSH9IgvQ6t29dH5IeYtFzwP+spP15AghS2B/vvpoj/NzYSo9dE7c/xR
                    qEMMp/FYKVRQ5J9y/nrPIppYFpOw6AsYgTxKILmx5FF3UGjuqHdRXI/epUDylfgB
                    AAD2h2D6Re0EDnYt4vLlEdxoknMyopI80XYwW4lIIPepTsEHmgEyadhXdFQVr/5B
                    wj/q2DstVL8/8SXKqeZvZae4I+E8S1pbsilJHxV2aS7tgUTvNeIKsWiXEV3SmA2N
                    +4YV2ipRuPJZ+vO3RIAGApNhFDKBfuaq6Jm4rMTR3TaCQH25wbXbdq6mM3TtdALk
                    OrAMb6sF2o1DrI0vj0sAKfExLHAIaiHp2lz2OBfNPVIwf2/Ran6SshZ33j9Yb4ei
                    wUWkJcoSPTIBC8JXOQF/HfB8dL+xxhjrJcpQJMarBQ8hxDsx2ccCAwEAAaNjMGEw
                    HQYDVR0OBBYEFM19INv8epriYePOaPiYL8y349iXMB8GA1UdIwQYMBaAFJ7vzqb8
                    edZIDz2ZVIkiJkuCFGbMMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIE
                    MA0GCSqGSIb3DQEBCwUAA4ICAQADFUIGtksG19PMnfpxz1oi3+EUeMNc/2OfNIry
                    CSqJt12pYgQxpW0R7glRrDT9JLw6Dajlt6jOSfl25PzcNUsE+twnp3Q4nTcMH1DD
                    OGuWviQJRuGlkb1GiasqgWaQXNmQEPUwcT85Bzv3h9aH1lnMeWSiQQ7F9dpS0qHV
                    JjO+yaHdcWHVtOtT9QGqH2P2GyuRnTimR/TJW1LaQHM8m7Ny4dAVhz86d/cYqY5s
                    r74fPnBSghyTDEUE8zTCU3SkWv+ykAbc+h1B+VpNH4hYm1Zj7HkJAOLFm8QYX0p6
                    haHo32DI4H3ttjdD4VVA5DiABbUom8goQeNjEU9bOl/WYsf/nYrLKkSSu30047Pf
                    gxl7UQcov7Xncs2/frytjKVd6L1zWNS3aIqNVMhJTPq1zADMJH1WFP1b77NVJyIB
                    8O3kuAlbMNILtg/eBhcD5o/8uuR0q0ikfKBWJSxWnf10BmkBkdAHeuFAC2GT+kkj
                    HGX2o+Q36X0dOBsu2FD5TOdNd8hYCRXyL2FoY+cm1JjziEK2bVoghgGq7iTNON3s
                    XtQbmOJ2ROpnk7rLKfsrydV9slH5UTe/25Eh9v4ORZOhwG/KA8KzlF2Jw24n+GU3
                    zZSjZuOjK9dFoPweg6XQkyH5zcQyZ1MpmbRTQR3O0wp6SGfdWhawY6+wP1/Yg7Ca
                    RZUuGg==
                    -----END CERTIFICATE-----""";

            certs_RSA.add(parseCert(str));

            str = """
                    -----BEGIN CERTIFICATE-----
                    MIIFQTCCAymgAwIBAgIQYtQ3fMcTehyJlxjFD+BUFDANBgkqhkiG9w0BAQsFADAb
                    MRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIwMDkyODIwMTY1MFoXDTMw
                    MDkyNjIwMTY1MFowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3
                    ZTczZjJhNzVmYjllZDZkYTViZjNlODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
                    AgoCggIBANbbOT706t8OMUIx1hRGPcwPbaDvruVxbkx9K1QNFZzAFFu8faxHWjqe
                    um/VPAoaWxo7/pLXJ/1zkhABhTlcB3/aTQWnzxauwXGjZoj0HiUtQj2AoX6RCJX3
                    HN5hh9FQblE/JoR0/DoJPo/zPWv8OrpQcl06gyBKInTJNKD/+xVwTim6GlEQT754
                    UF39C+KoogzbwJGgfpT6Jdj08ork11mFOmQb8dszrN8oLzpmcfo83gUmLRKvHBue
                    TTN/aR/KtVjgsKxSdLgyyZ699A5vBzoFAsQu+lQvqckCF1Qx91wKcIkeYx03pM+4
                    zKquYe3OhUG5lwqaWsOhRVGpiU7iaFj6VMeInL7gBjS9LE42xnbItM1N4ZbJg5N7
                    qe4G4ZcQuZI8rEk9kjRgL91zgjQCIie3FU+UpvJSPpjsPjoWCv6paH9VCRcWlXo7
                    IP2RfTQXBohBznAh7abubK8ujNMa80i3uXN3Q2G0Jr/hIvCGMtNmzE+uPz79FEZG
                    PjKwO9XX2XtDBXzhgBs+AoV0ODswSbkFOamharOiT+Vq2U1BviDF/O1yzO53EP4S
                    weaLGsWznwVA7wppkmk2G2p1WjWJ6prBMYNoKLmArq+B5uZAFdLl+r9dy4gNkFyc
                    g10akANoSQIir+gb+DkiH1kgVuoO8+icTExwxaIdIhk9KWhEz1H3AgMBAAGjYzBh
                    MB0GA1UdDgQWBBSe786m/HnWSA89mVSJIiZLghRmzDAfBgNVHSMEGDAWgBQ2YeEA
                    fIgFCVGLRGxH/xpMyepPEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIC
                    BDANBgkqhkiG9w0BAQsFAAOCAgEACmD/wwX1+pNXfct3/q7AYnznjKo5C3MUFNPd
                    IJ9zYL74PbitMy50NU1XhVAs1uqjsUN+qgOxU9w2rz/0a1yf+2QLGGVFywbjP1Tt
                    /hZX8Ka04iVdnr7AyObloz9KchTE431wPGXrpEw5/NXr6yvmeUSxKYe1aJBrqHc3
                    xROh0+WkTHBiLBnlcFr5nmxYrVPDcC9sBwaU6TQvc2JUcBwIu5WowyItgeDrq+8h
                    0HcpomcHcqrfuEMnO/9LZIQECIf8rTc6k7mD8hL+xOWuqMO48eC8g9xwKXKjEfRo
                    /RZrM5uW/qP8E1JZyD81J4H0aW1hsuNvd/puUMj9EjWYZW/ud4r15fSJ9LYniJER
                    rpnUmB43wORBf6x29akHDXyohd6QbunpEhy7HBw7IzZ6ZemZ2zAcDfcI5KiGEyAu
                    scG3ov+WtGPq39NEc0ux5ipnO9ETkS50BDByFrGeZsGdpGBwK4xYLhmFPVzEaFDk
                    FOpBEzxfdkMBQX/5PMqYiWkLS8EoyCsdmnua07zs3qQtkXC7sQjwaK9h/FwkEdt/
                    CdtLvbZUpzd1I/qHJzIuAWhwPBLsCSvSaq+cSEvBPkhVmLJJY+dlkv6zPEo10hv5
                    y11KV3n/6sIxYNL4TGF1enD64ysmsEy1A6g4UkmMpaHePbLiyb6Ri26TKY7G+wuP
                    fmjXsWI=
                    -----END CERTIFICATE-----""";

            certs_RSA.add(parseCert(str));

            str = """
                    -----BEGIN CERTIFICATE-----
                    MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
                    BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAz
                    NzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
                    AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
                    Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
                    tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
                    nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
                    C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
                    oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
                    JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
                    sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
                    igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
                    RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
                    aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
                    AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
                    IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
                    VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnu
                    XKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
                    h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cno
                    L/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2ok
                    QBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
                    D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAI
                    mMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoW
                    Fua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
                    oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09o
                    jm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUB
                    ZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
                    ex0SdDrx+tWUDqG8At2JHA==
                    -----END CERTIFICATE-----""";

            certs_RSA.add(parseCert(str));


        } catch (Throwable t) {
            XposedBridge.log(t);
            throw new RuntimeException(t);
        }
    }

    private static KeyPair parseKeyPair(String key) throws Throwable {
        Object object;
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            object = parser.readObject();
        }

        PEMKeyPair pemKeyPair = (PEMKeyPair) object;

        return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    }

    private static Certificate parseCert(String cert) throws Throwable {
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }

        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());

        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static Extension addHackedExtension(Extension extension) {
        try {
            ASN1Sequence keyDescription = ASN1Sequence.getInstance(extension.getExtnValue().getOctets());

            ASN1EncodableVector teeEnforcedEncodables = new ASN1EncodableVector();

            ASN1Sequence teeEnforcedAuthList = (ASN1Sequence) keyDescription.getObjectAt(7).toASN1Primitive();

            for (ASN1Encodable asn1Encodable : teeEnforcedAuthList) {

                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;

                if (taggedObject.getTagNo() == 704) continue;

                teeEnforcedEncodables.add(taggedObject);
            }

            SecureRandom random = new SecureRandom();

            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            random.nextBytes(bytes1);
            random.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(bytes1), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(bytes2)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            ASN1TaggedObject rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);

            teeEnforcedEncodables.add(rootOfTrust);

            var attestationVersion = keyDescription.getObjectAt(0);
            var attestationSecurityLevel = keyDescription.getObjectAt(1);
            var keymasterVersion = keyDescription.getObjectAt(2);
            var keymasterSecurityLevel = keyDescription.getObjectAt(3);
            var attestationChallenge = keyDescription.getObjectAt(4);
            var uniqueId = keyDescription.getObjectAt(5);
            var softwareEnforced = keyDescription.getObjectAt(6);
            var teeEnforced = new DERSequence(teeEnforcedEncodables);

            ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

            ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

            ASN1OctetString keyDescriptionOctetStr = new DEROctetString(keyDescriptionHackSeq);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);

        } catch (Throwable t) {
            XposedBridge.log(t);
        }

        return extension;
    }

    private static Extension createHackedExtensions() {
        try {
            SecureRandom random = new SecureRandom();

            byte[] bytes1 = new byte[32];
            byte[] bytes2 = new byte[32];

            random.nextBytes(bytes1);
            random.nextBytes(bytes2);

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(bytes1), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(bytes2)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            ASN1Integer[] purposesArray = {new ASN1Integer(0), new ASN1Integer(1), new ASN1Integer(2), new ASN1Integer(3), new ASN1Integer(4), new ASN1Integer(5)};

            ASN1Encodable[] digests = {new ASN1Integer(1), new ASN1Integer(2), new ASN1Integer(3), new ASN1Integer(4), new ASN1Integer(5), new ASN1Integer(6)};

            var Apurpose = new DERSet(purposesArray);
            var Aalgorithm = new ASN1Integer(3);
            var AkeySize = new ASN1Integer(256);
            var Adigest = new DERSet(digests);
            var AecCurve = new ASN1Integer(1);
            var AnoAuthRequired = DERNull.INSTANCE;
            var AosVersion = new ASN1Integer(130000);
            var AosPatchLevel = new ASN1Integer(202401);
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

            ASN1Integer attestationVersion = new ASN1Integer(4);
            ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
            ASN1Integer keymasterVersion = new ASN1Integer(41);
            ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
            ASN1OctetString attestationChallenge = new DEROctetString(attestationChallengeBytes);
            ASN1OctetString uniqueId = new DEROctetString("".getBytes());
            ASN1Sequence softwareEnforced = new DERSequence();
            ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

            ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

            ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

            ASN1OctetString keyDescriptionOctetStr = new DEROctetString(keyDescriptionHackSeq);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);

        } catch (Throwable t) {
            XposedBridge.log(t);
        }
        return null;
    }

    private static Certificate createLeafCert() {
        try {
            long now = System.currentTimeMillis();
            Date notBefore = new Date(now);

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(notBefore);
            calendar.add(Calendar.HOUR, 1);

            Date notAfter = calendar.getTime();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(new X500Name("CN=chiteroman"), BigInteger.ONE, notBefore, notAfter, new X500Name("CN=Android Keystore Key"), keyPair_EC.getPublic());

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

            certBuilder.addExtension(createHackedExtensions());

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair_EC.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(contentSigner);

            return new JcaX509CertificateConverter().getCertificate(certHolder);

        } catch (Throwable t) {
            XposedBridge.log(t);
        }
        return null;
    }

    private static Certificate hackLeafExistingCert(Certificate certificate) {
        try {
            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());

            KeyPair keyPair;
            if (KeyProperties.KEY_ALGORITHM_EC.equals(certificate.getPublicKey().getAlgorithm())) {
                keyPair = keyPair_EC;
            } else {
                keyPair = keyPair_RSA;
            }

            long now = System.currentTimeMillis();
            Date notBefore = new Date(now);

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(notBefore);
            calendar.add(Calendar.HOUR, 1);

            Date notAfter = calendar.getTime();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(certificateHolder.getIssuer(), certificateHolder.getSerialNumber(), notBefore, notAfter, certificateHolder.getSubject(), keyPair.getPublic());

            for (Object extensionOID : certificateHolder.getExtensionOIDs()) {

                ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) extensionOID;

                if ("1.3.6.1.4.1.11129.2.1.17".equals(identifier.getId())) continue;

                certBuilder.addExtension(certificateHolder.getExtension(identifier));
            }

            Extension extension = certificateHolder.getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"));

            certBuilder.addExtension(addHackedExtension(extension));

            ContentSigner contentSigner;
            if (KeyProperties.KEY_ALGORITHM_EC.equals(certificate.getPublicKey().getAlgorithm())) {
                contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
            } else {
                contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            }

            X509CertificateHolder certHolder = certBuilder.build(contentSigner);

            return new JcaX509CertificateConverter().getCertificate(certHolder);

        } catch (Throwable t) {
            XposedBridge.log(t);
        }
        return certificate;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {

        if (!lpparam.isFirstApplication) return;

        final var systemFeatureHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String featureName = (String) param.args[0];

                if (PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(featureName))
                    param.setResult(Boolean.FALSE);
                else if (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(featureName))
                    param.setResult(Boolean.FALSE);
                else if ("android.software.device_id_attestation".equals(featureName))
                    param.setResult(Boolean.FALSE);
            }
        };

        try {
            Application app = AndroidAppHelper.currentApplication();

            Class<?> PackageManagerClass, SharedPreferencesClass;

            if (app == null) {
                PackageManagerClass = XposedHelpers.findClass("android.app.ApplicationPackageManager", lpparam.classLoader);
                SharedPreferencesClass = XposedHelpers.findClass("android.app.SharedPreferencesImpl", lpparam.classLoader);
            } else {
                PackageManagerClass = app.getPackageManager().getClass();
                SharedPreferencesClass = app.getSharedPreferences("settings", Context.MODE_PRIVATE).getClass();
            }

            XposedHelpers.findAndHookMethod(PackageManagerClass, "hasSystemFeature", String.class, systemFeatureHook);
            XposedHelpers.findAndHookMethod(PackageManagerClass, "hasSystemFeature", String.class, int.class, systemFeatureHook);

            XposedHelpers.findAndHookMethod(SharedPreferencesClass, "getBoolean", String.class, boolean.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String key = (String) param.args[0];

                    if ("prefer_attest_key".equals(key)) param.setResult(Boolean.FALSE);
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }

        try {
            XposedHelpers.findAndHookMethod(KeyGenParameterSpec.Builder.class, "setAttestationChallenge", byte[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    attestationChallengeBytes = (byte[]) param.args[0];
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }

        try {
            KeyPairGeneratorSpi keyPairGeneratorSpi_EC = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGeneratorSpi_EC.getClass(), "generateKeyPair", new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    return keyPair_EC;
                }
            });
            KeyPairGeneratorSpi keyPairGeneratorSpi_RSA = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            XposedHelpers.findAndHookMethod(keyPairGeneratorSpi_RSA.getClass(), "generateKeyPair", new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) {
                    return keyPair_RSA;
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyStoreSpi keyStoreSpi = (KeyStoreSpi) XposedHelpers.getObjectField(keyStore, "keyStoreSpi");
            XposedHelpers.findAndHookMethod(keyStoreSpi.getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Certificate[] certificates = null;

                    try {
                        certificates = (Certificate[]) param.getResultOrThrowable();
                    } catch (Throwable t) {
                        XposedBridge.log(t);
                    }

                    LinkedList<Certificate> certificateList = new LinkedList<>();

                    if (certificates == null) {

                        certificateList.addAll(certs_EC);
                        certificateList.addFirst(createLeafCert());

                    } else {
                        if (!(certificates[0] instanceof X509Certificate x509Certificate)) return;

                        byte[] bytes = x509Certificate.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");

                        if (bytes == null || bytes.length == 0) return;

                        String algorithm = x509Certificate.getPublicKey().getAlgorithm();
                        if (KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)) {

                            certificateList.addAll(certs_EC);

                        } else if (KeyProperties.KEY_ALGORITHM_RSA.equals(algorithm)) {

                            certificateList.addAll(certs_RSA);
                        }
                        certificateList.addFirst(hackLeafExistingCert(x509Certificate));
                    }

                    param.setResult(certificateList.toArray(new Certificate[0]));
                }
            });
        } catch (Throwable t) {
            XposedBridge.log(t);
        }
    }
}