# Learning SSL/TLS
## [Course Certificate](https://www.linkedin.com/learning/certificates/9e048b14b8b31b946a80bf3047496b4a2d122b7fe990ce95ec42f54dc247b6ef)

> This is to Understand Code Sign Process <br>
----

1. ### Environment:
    - Microsoft Windows Server Machine: to support PKI & active directory domain.
    - Kali Linux

2. ### Cryptographic Keys:
    - Stored in:
        1. PKI certificate.
        2. CAC Smart Card (Common Access Card).
        3. Password-protected file.
        4. TPM (Trusted Platform Module).
        5. Token Devices.

3. ### General Encryption Process:
    - Plaintext is fed into an encryption algorithm.
    - Key is used with the encrypted algorithm.
    - Encryption Algorithm results in encrypted data (ciphertext).
    - Only parties with decryption key can decrypt the ciphertext.

4. ### Where is Cryptography used:
    - Mobile Device Encryption
    - File system encryption
    - Network traffic encryption
    - File hashing
    - cryptoCurryency blockchain. 

5. ### Symmetric Encryption:
    - Uses 'single' secret key
    - The secret key encrypts and decrypts
    - All parties require the key.
    - Key must be kept secure
    - Symmetric Encryption Algorithms:
        - AES 256 is the key size.
        - RC4 
        - 3DES
        - Blowfish

6. ### Asymmetric Encryption:
    - Uses two mathematically related keys.
    - Public and private key.
    - Used by PKI
    - Asymmetric Encryption Algorithms:
        - RSA
        - Diffie-Hellman
        - ElGamal
        - ECC

7. ### SSL/TLS Network Security:
    - Secure Communication.
    - PKI (Public Key Infrastructure) Hierarchy:
        1. CA (Certificate Authority) => issue, renew, revoke certificates, maintains CRL; should be taken offline
        2. RA (Registration Authority) => subordinate CA; should be used to manage certificates
        3. CRL (Certificate Revocation List) or OCSP (Online Certificate Status Protocol) => Verification of certificate validity using serial number
        4. Certificate Template => Blueprint used when issuing certificates.
        5. Certificate that contains everything => constains subject name, signature of CA and expiry information, public/private key.
    - Single-Tier PKI Hierarchy.
    - Multi-Tier PKI Hierarchy.

8. ### Certificate Authorities:
    - Issue, revoke, renew certificates.
    - Publish a Certificate Revocation List (CRL).
    - Chain of Trust.
    - CAs need to be trusted.
    - No SSL/TLS without PKI certificates.
    - Certificates are issued to users, devices, applications.
    - PKI includes:
        - OCSP (Online Certificate Status Protocol).
        - OCSP Stapling.
        - Certificate Life Cycle.
- PKI Certificates => also called X.509 certificates.
- PKI Certificate includes:
    - Version number.
    - Serial number.
    - CA digital signature and algorithm used. 
    - Validity period.
    - Certificate usage details.
    - Subject name, URL, email address.
    - Public/Private key
- OCSP Stapling
- PKP 
- Certificate Lifecycle:
    1. Certificate request:
        - a public and private key pair is generated first.
        - private keys can be copied or made available to the trusted third parties (key escrow)
        - CSR is generated next, which includes a unique public key, commonly in PKCS #10 format
        - CSR is sent to a certificate authority for signing. 
        
    2. Certificate issuance
        - Process can be manual, which could require administrator approval before certificate is issued
        - Process could be automated for new devices
        - The certificate can be stored in the device-trusted certificate store or other media such as a smart card.

    3. Certificate usage
        - Defined in the certificate details.
        - Email encryption and signing.
        - File system encryption.
        - Code signing.
        - Apps can first verify the validity of a certificate before using them (CRL and OCSP)

    4. Certificate revocation
        - Certificate compromise.
        - Employee leaving the organization.
        - The certificate serial number for revoked certificates can be acquired via the CRL or the OCSP

    5. Certificate renewal
        - Certificate expiry is security mechanism
        - Time frame varies depending on issuer; the norm is two years.
        - Manual or automated (automation such as through SCEP)
        - Public CAs notify subscribers via email
        - Renewal must occur before certificate expiration
    6. Certificate expirey
        - Appears in the certificate as dates. 
9. ### PKI Implementation.
    - Install a Microsoft AD CS certificate authority.
    - Configure Microsoft AD CS Certificate template.
    - Configure a Linux OpenSSL PKI environment:
        - `openssl genrsa -aes256 -out CAprivate.key 2048`
        - `openssl req -new -x509 -key CAprivate.key -sha256 -days 365 -out Fakedomain2CA.pem`
        - if you do `ls` both CAprivate.key and Fakedomain2CA.pem are listed in your directory.
    - Configure an AWS Certificate Manager subordinate CA:
        - Sign in to AWS
        - Go to Management Console
        - Select Certificate Manager
        - Select `Get started` with Private Certificate Authority
        - You will only have a choice for subordinate CA because you already have a root CA 
        - Click `Next` so you will be directed to Configure CA name, Fill the details. 
        - Then click `Next`, the default algorithm is RSA 2048 so click `Next` again and keep settings as they are then review your subordinate certificate information so click `Confirm and create`.
        - If CA is created successefully so get the CRS for the CA.
        - Request the certificate then submit your Certificate request. 
        - Then download the certificate and the certificate chain. 
        - Import the certificate body to AWS
        - Finally check if certificate is issued in `certsrv` Issued certificates. 
        
10. ### PKI Certificate Acquisition:
    - SSL vs. TLS.
        - Both use PKI certificates and related keys to secure network communication.
        - Encryption Confidentiality.
        - Digital signatures and hashing(authentication, integrity, non-reputation)
        - Both are application-specific (Must be configured separately for HTTP, SMTP and so on)
    - **SSL**:
        - Secure Sockets Layer
        - Developed by Netscape in the ealy 1990s
        - SSL v1-v3, none of these should be used unless required for legacy  interoperability.
        - Superseded by TLS
        - SSL should be disabled on servers due to security vulnerabilities.
    - **SPDA**:
        - Security Protocol Downgrade Attacks
        - PKI Certificates are not specific to SSL or TLS; server and client configuration are. 
        - During the initial handshake, client and server agree on which specific SSL or TLS version to use.
        - Many MITM attacks try to downgrade the security protocol used; TLS_FALLBACK_SCSV mitigates this
        - Disable SSL, enable TLS 1.1 or better
    - **POODLE Attack**:
        - Padding Oracle On Downgraded Legacey Encryption (POODLE)
        - Affects SSL v3 released in 1996
        - Malicious JS is injected into a victim's web browser into using SSL v3 instead of TLS
        - Secure HTTP session cookies could be compromised.
    - **Heartbleed Bug**:
        - Vulnerablility.
    - **TLS**:
        - Transport Security Layer.
        - Introduced in 1999
        - Replaces SSL
        - Comply some standards with PCI DSS
    - **SSL VPN**:
        - Virtual Private Networks
        - Firewall friendly. 
    - **Client Security Protocol Configuration**:
        - Disable certian Protocols.
        - Check if TLS Support on Linux `openssl ciphers -v` 
        - `certmgr` => certlm => Local computer certificates
        - `mmc` Micorsoft Management Console
        - 

    

11. ### PKI Certificate Usage:
    - **Hashing and digital signatures**:
        - Used to verify integrity of network messages, files, and machine boot-up settings.
        - Does not provide data confidentiality.
        - Used with SSL and TLS
        - Uses a one-way algorithm that results in a unique value(Hash, message digest)
    - Common Hashing Algorithms:
        - Sha-1: 160-bit hashes
        - Sha-2: 
        - sha-3:
        - MD5: message digest.
        - RIPEMD
    - **Digital Signature**:
        - Provide data authentication, integrity, and non-repudiation.
        - Does not provide data confidentiality.
        - Used with SSL and TLS , applications, scripts device drivers.
        - Encrypts a hash value using a private key.
        - The signature is verified with the matching public key
    - **Email Digital Signatures**:
        - Can assign encryption manually.
    - Configure a website with a certificate.
    - Configure a web browser with a certificate
    - Configure a code signing certificate with Microsoft PowerShell.
        - `certsrv` certificate server.
        - Windows Powershel ISE
    - Encrypting file system and certificate
        - Basic EFS => Third party
        - Computer certificates differ from User certificates
    - Configure a TLS VPN
        - From server manager add roles and access.
        - Choose custome configuration.
        - `Regedit` => Registery Editor
        - Then Network and Sharing for adding a new network.
        - SSTP is there, connect from VPN 

12. ### Conclusion.
    - Try other PKI prodcuts(private and public CAs)
    - Research known SSL v3 and TLS v1.0 vulnerablilities
    - Experiment with additional certificate templates
    - Microsoft Active Directory Group Policy
    - Automate certificate deployment.

