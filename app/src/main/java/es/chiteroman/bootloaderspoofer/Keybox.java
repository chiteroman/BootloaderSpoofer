package es.chiteroman.bootloaderspoofer;

public class Keybox {
    public static final String XML = """
            <?xml version="1.0"?>
            <AndroidAttestation>
            	<NumberOfKeyboxes>1</NumberOfKeyboxes>
            	<Keybox DeviceID="X705F100000000">
            		<Key algorithm="ecdsa">
            			<PrivateKey format="pem">
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIA2Pc+RjAdMyqaCpctIuSyCGhsPnTHPeOxhM7QmGb1gNoAoGCCqGSM49
            AwEHoUQDQgAEWu/pudQWIK+TPC7f9dftyxq5te8xMChNHYALeeiB6zk8laiG9zu9
            cae9EY763/thIoZQXQTVQK43+QHcKnOetQ==
            -----END EC PRIVATE KEY-----
            </PrivateKey>
            			<CertificateChain>
            				<NumberOfCertificates>3</NumberOfCertificates>
            				<Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            MIICJTCCAaugAwIBAgIKEJl1VCCDF2mHUzAKBggqhkjOPQQDAjApMRkwFwYDVQQF
            ExA4YWJlMWM3NWRjMWNkNTk5MQwwCgYDVQQMDANURUUwHhcNMTgwNDE4MjEzMzQ5
            WhcNMjgwNDE1MjEzMzQ5WjApMRkwFwYDVQQFExA2MGYyMjlmMTlmY2EzYTA0MQww
            CgYDVQQMDANURUUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARa7+m51BYgr5M8
            Lt/11+3LGrm17zEwKE0dgAt56IHrOTyVqIb3O71xp70Rjvrf+2EihlBdBNVArjf5
            Adwqc561o4G6MIG3MB0GA1UdDgQWBBSriAVmksHYWuCRLlDvR47MzfcUfDAfBgNV
            HSMEGDAWgBSQv/MlEz9XMxBFdPp9W+RNB1737TAPBgNVHRMBAf8EBTADAQH/MA4G
            A1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQu
            Z29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzEwOTk3NTU0MjA4MzE3Njk4
            NzUzMAoGCCqGSM49BAMCA2gAMGUCMQDx5cRqI58iDdXLDkD0rvh1fjOSmejV5NCH
            +KX5A2mZLzxxy8QkW3szHck0qvarVK0CMGDi3tjaKLiM3rPHyAJmltRDIvLZejwz
            R+0oP0cs/vld5xBZSoXbvjCPe39IQryn7Q==
            -----END CERTIFICATE-----
            </Certificate>
            				<Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            MIID0TCCAbmgAwIBAgIKA4gmZ2BliZaFkTANBgkqhkiG9w0BAQsFADAbMRkwFwYD
            VQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MDQxODIxMTQ1NloXDTI4MDQxNTIx
            MTQ1NlowKTEZMBcGA1UEBRMQOGFiZTFjNzVkYzFjZDU5OTEMMAoGA1UEDAwDVEVF
            MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEiejPFIryi9AYM9zV6pGpIFaVpPgdB+zI
            jJSPgDcZkeDL5Y9Sie0/aAopayrp5UYs+zxRKHIZjAXS9HWOzGg/PIxBa1Fl0tRz
            HPLGiW1BIrc8pEK+6AJ429QTJoSn4h/No4G2MIGzMB0GA1UdDgQWBBSQv/MlEz9X
            MxBFdPp9W+RNB1737TAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH/xpMyepPEjAP
            BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BB
            hj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3Js
            L0U4RkExOTYzMTREMkZBMTgwDQYJKoZIhvcNAQELBQADggIBAAt4xKMpMK52papq
            k/QhULlXzaJrYLfLOmvOo1oP4urFcZD7Usk7G2HNoJM2qg3qgjawcUrAov7ZNekl
            Uc8ZSozY3yJiHGGNRNezXDDPnj+v+XAjE5I46iG3WoZvMYaa0GK5qNMf9v1/UScN
            D517vhSJIuFjsZjZOHbS83dit7JOoJ/e+5WnLdgdvMpixgkvXrp6Y9DlBFY5c2FY
            9i1MsPi9WDpylxAigB8g4bcZ0/fsMhLTUiGuenaS4c6TrKaqWBBcTtYdpECNJ+bE
            FowbW9nxOaI88deIxnldvFpms9XZw/amAx8y2hwoC5kLzhAAcjIidn2oKiTQr1zI
            C2iVnFWyE8z+T7s//KKfzYLFm5h9YdW7n87j3PkRW5zZOVUzg2a5n/ME8qbCdYQV
            Qe2ouog4Z/Tu/dwocEeH1jQaiAjqtliiLyJD0XaFqxvGf49IyRFuxq5eK5EAx2Cv
            GoJLFqL2jIvxdSyOxd58s6I9EnomS6hFWsmwNsuVKxFtnI+Okv1mLm4C8qwVxx6f
            SQBUJTtUmK/hliL42cjtAfHqVyYM4xV7F8MP10ncEB0hG2yua5g5Y4Ds3wcVIp5Z
            USgFL9I0raZrb91fJPYetHbb/rrSRp/h805f7Ilf2cApZenzlgcf8JzZ2PuKxWsA
            a/UNhoh2zVkWkGJr00lp8Df1RYXM
            -----END CERTIFICATE-----
            </Certificate>
            				<Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            </Certificate>
            			</CertificateChain>
            		</Key>
            		<Key algorithm="rsa">
            			<PrivateKey format="pem">
            -----BEGIN RSA PRIVATE KEY-----
            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
            -----END RSA PRIVATE KEY-----
            </PrivateKey>
            			<CertificateChain>
            				<NumberOfCertificates>3</NumberOfCertificates>
            				<Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            yeUhJXg=
            -----END CERTIFICATE-----
            </Certificate>
            				<Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            9CyCxsjOYp45mn6Um/+dbYjSZw==
            -----END CERTIFICATE-----
            </Certificate>
            				<Certificate format="pem">
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            </Certificate>
            			</CertificateChain>
            		</Key>
            	</Keybox>
            </AndroidAttestation>""";
}
