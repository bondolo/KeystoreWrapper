/*
 */
package org.bondolo.keystore;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Container that handles persistence for a PKCS12 keystore and makes usage more
 * convenient.
 *
 * <p>Methods and constructors will typically throw {@code NullPointerException}
 * for null parameters unless otherwise explicitly specified.
 */
public class KeyStoreContainer implements Destroyable {

    /**
     * Standard clock drift allowed for crypto-period of issued certs, 1 hour for daylight savings time and 1 minute for clock skew
     */
    public static final Duration MAX_CLOCK_DRIFT = Duration.ofHours(1).plusMinutes(1);
    /**
     * Certificates will be valid for approximately 10 years
     */
    public static final Period CERTIFICATE_CRYPTO_PERIOD = Period.ofYears(10);
    /**
     * Tombstone store password used to mark that key store container has been
     * destroyed
     */
    private static final char[] DESTROYED = new char[0];
    /**
     * Size of RSA keys generated
     */
    private static final int RSA_KEY_SIZE = 3072; // per FIPS 186-4
    /**
     * The logger we shall use
     */
    private final static Logger logger = Logger.getLogger(KeyStoreContainer.class.getSimpleName());
    /**
     * The keystore location or null if read-only keystore
     */
    private final URI location;
    /**
     * In-memory cache of the keystore
     */
    private final @NonNull KeyStore keystore;
    private final @NonNull PasswordMapper keyPassword;
    /**
     * Crypto Algorithms provider. Null for default provider chain
     */
    private final @Nullable Provider provider;
    /**
     * Supplier for SecureRandom instances.
     */
    private final @NonNull Supplier<SecureRandom> secureRandomSupplier;
    /**
     * The keystore password
     */
    private volatile char @Nullable [] storePassword;
    /**
     * Create a non-persistent keystore container
     *
     * @param keystore             The keystore instance to be managed
     * @param source               The keystore source or null for new keystore
     * @param storePassword        The key store password or null for none
     * @param keyPassword          mapper from alias to key password
     * @param provider             The crypto provider
     * @param secureRandomSupplier A supplier for {@link SecureRandom} instances.
     * @throws IOException          for errors reading the keystore
     * @throws NullPointerException for null arguments
     */
    public KeyStoreContainer(@NonNull KeyStore keystore, InputStream source, char[] storePassword, @NonNull PasswordMapper keyPassword, @Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws IOException {
        this(keystore,
                Objects.requireNonNull(source, "source"),
                null,
                storePassword,
                keyPassword, provider, secureRandomSupplier);
    }

    /**
     * Create a keystore container persisted using the provided path
     *
     * @param keystore             The keystore instance to be managed
     * @param location             The keystore location
     * @param storePassword        The key store password or null for none
     * @param keyPassword          mapper from alias to key password.
     * @param provider             The crypto provider
     * @param secureRandomSupplier A supplier for {@link SecureRandom} instances.
     * @throws IOException          for errors reading the keystore
     * @throws NullPointerException for null arguments
     */
    public KeyStoreContainer(@NonNull KeyStore keystore, @NonNull Path location, char[] storePassword, @NonNull PasswordMapper keyPassword, @Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws IOException {
        this(keystore,
                location.toUri(),
                !(Files.isWritable(location) || (!Files.exists(location) && Files.isWritable(location.toAbsolutePath().getParent()))),
                storePassword,
                keyPassword, provider, secureRandomSupplier);
    }

    /**
     * Create a non-persistent keystore container from the provided path
     *
     * @param keystore             The keystore instance to be managed
     * @param location             The keystore location
     * @param readonly             if true then the keystore is non-persistent
     * @param storePassword        The key store password or null for none
     * @param keyPassword          mapper from alias to key password.
     * @param provider             The crypto provider
     * @param secureRandomSupplier A supplier for {@link SecureRandom} instances.
     * @throws IOException          for errors reading the keystore
     * @throws NullPointerException for null arguments
     */
    public KeyStoreContainer(@NonNull KeyStore keystore, @NonNull URI location, boolean readonly, char[] storePassword, @NonNull PasswordMapper keyPassword, @Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws IOException {
        this(keystore,
                KeyStoreContainer.openInput(location),
                readonly ? null : location,
                storePassword,
                keyPassword, provider, secureRandomSupplier);
    }

    /**
     * Create a keystore container
     *
     * @param keystore             The keystore instance to be managed
     * @param source               The keystore source or null for new keystore
     * @param location             The storage location of the keystore or null for
     *                             non-persistent key stores
     * @param storePassword        The key store password or null for none
     * @param keyPassword          mapper from alias to key password
     * @param provider             The crypto provider
     * @param secureRandomSupplier A supplier for {@link SecureRandom} instances.
     * @throws IOException          for errors reading the keystore
     * @throws NullPointerException for null arguments
     */
    protected KeyStoreContainer(@NonNull KeyStore keystore, @Nullable InputStream source, URI location, char @Nullable [] storePassword, @NonNull PasswordMapper keyPassword, @Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws IOException {
        this.provider = provider;
        this.location = location;
        this.storePassword = null != storePassword ?
                Arrays.copyOf(storePassword, storePassword.length)
                : null;
        this.keyPassword = Objects.requireNonNull(keyPassword, "keyPassword");
        this.keystore = Objects.requireNonNull(keystore, "keystore");
        this.secureRandomSupplier = Objects.requireNonNull(secureRandomSupplier, "secureRandomSupplier");
        try {
            keystore.load(null != source ? new BufferedInputStream(source) : null, this.storePassword);
            logger.info((null != source ? "Read" : "Initialize") + " keystore size=" + keystore.size());
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException ex) {
            throw new IOException("Security failure reading keystore", ex);
        }
    }

    /**
     * Opens an input stream for the provided location
     *
     * @param uri The source location of the input stream
     * @return The unbuffered input stream or null if the location is unreadable
     * or the file is empty
     * @throws IOException          if the source location cannot be read
     * @throws NullPointerException if the source location is null
     */
    protected static @Nullable InputStream openInput(@NonNull URI uri) throws IOException, NullPointerException {
        if ("file".equalsIgnoreCase(Objects.requireNonNull(uri, "uri").getScheme())) {
            Path path = Paths.get(uri);
            return Files.isReadable(path) && Files.size(path) > 0
                    ? Files.newInputStream(path)
                    : null;
        } else {
            URLConnection connection = uri.toURL().openConnection();
            connection.setUseCaches(false);
            connection.setAllowUserInteraction(false);
            return connection.getInputStream();
        }
    }

    /**
     * Opens an output stream for the provided location
     *
     * @param uri The source location of the output stream
     * @return The unbuffered output stream
     * @throws IOException          if the source location cannot be written
     * @throws NullPointerException if the output location is null
     */
    protected static OutputStream openOutput(@NonNull URI uri) throws IOException, NullPointerException {
        if ("file".equalsIgnoreCase(uri.getScheme())) {
            return Files.newOutputStream(Paths.get(uri));
        } else {
            URLConnection connection = uri.toURL().openConnection();
            connection.setDoOutput(true);
            return connection.getOutputStream();
        }
    }

    private static @NonNull String toHexString(byte @NonNull [] bytes) {
        StringBuilder alias = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            alias.append(String.format("%02x", b));
        }
        return alias.toString();
    }

    @Override
    public boolean isDestroyed() {
        return DESTROYED == storePassword;
    }

    @Override
    public void destroy() {
        char[] current = storePassword;
        storePassword = DESTROYED;

        if (null != current)
            Arrays.fill(current, (char) 0);
    }

    /**
     * Returns true if the key store is persistent
     *
     * @return true if the key store is persistent otherwise false if the
     * keystore is non-persistent.
     */
    public boolean isPersistent() {
        return null != location;
    }

    /**
     * Returns location of the persistent key store or empty if non-persistent
     *
     * @return location of the persistent key store or empty if non-persistent
     */
    public @NonNull Optional<URI> location() {
        return Optional.ofNullable(location);
    }

    /**
     * Add or replace the provided certificate in the key store using using an
     * alias calculated from the SHA256 hash of the public key
     *
     * @param cert The certificate to be added
     * @return the alias of the certificate
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if the certificate cannot be added
     * @throws NullPointerException       if cert is null
     */
    public @NonNull String set(@NonNull X509Certificate cert) throws KeyStoreDestroyedException, IOException {
        String alias = toAlias(Objects.requireNonNull(cert, "cert").getPublicKey());
        KeyStoreContainer.this.set(alias, cert);
        return alias;
    }

    /**
     * Add or replace the provided certificate in the key store using using an
     * alias calculated from the SHA256 hash of the public key
     *
     * @param pemFile The certificate to be added
     * @return the alias of the certificate
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if the certificate cannot be added
     * @throws NullPointerException       if cert is null
     */
    public @NonNull String importPEM(@NonNull URI pemFile) throws KeyStoreDestroyedException, IOException {
        try (InputStream pem = openInput(pemFile)) {
            if (null == pem) {
                throw new IOException("Unusable PEM file");
            }
            return importPEM(pem);
        }
    }

    /**
     * Add or replace the provided certificate in the key store using using an
     * alias calculated from the SHA256 hash of the public key
     *
     * @param pemFile The certificate to be added
     * @return the alias of the certificate
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if the certificate cannot be added
     * @throws NullPointerException       if cert is null
     */
    public @NonNull String importPEM(@NonNull Path pemFile) throws KeyStoreDestroyedException, IOException {
        try (InputStream pem = Files.newInputStream(pemFile)) {
            return importPEM(pem);
        }
    }

    /**
     * Add or replace the provided certificate in the key store using an
     * alias calculated from the SHA256 hash of the public key
     *
     * @param pemStream The certificate to be added. The stream may be closed
     * @return the alias of the certificate
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if the certificate cannot be added
     * @throws NullPointerException       if cert is null
     */
    public @NonNull String importPEM(@NonNull InputStream pemStream) throws KeyStoreDestroyedException, IOException {
        X509Certificate cert;
        try {
            CertificateFactory factory = null != provider
                    ? CertificateFactory.getInstance("X.509", provider)
                    : CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) factory.generateCertificate(Objects.requireNonNull(pemStream, "pemStream"));
            return set(cert);
        } catch (CertificateException ex) {
            logger.log(Level.WARNING, "Security failure storing certificate", ex);
            throw new IOException("Security failure storing certificate", ex);
        }
    }

    /**
     * Exports the certificate specified as a PEM file to the specified path.
     *
     * @param alias   alias of the certificate to export
     * @param pemFile the destination file path.
     * @throws IllegalArgumentException if alias is not recognized
     * @throws IOException              if the certificate cannot be exported
     */
    public void exportPEM(@NonNull String alias, @NonNull Path pemFile) throws IOException {
        try (OutputStream pem = Files.newOutputStream(pemFile)) {
            exportPEM(alias, pem);
        }
    }

    /**
     * Exports the certificate specified as a PEM file to the specified output
     * stream.
     *
     * @param alias     alias of the certificate to export
     * @param pemStream the destination output stream. The stream is not closed
     * @throws IllegalArgumentException if alias is not recognized
     * @throws IOException              if the certificate cannot be exported
     */
    public void exportPEM(@NonNull String alias, @NonNull OutputStream pemStream) throws IOException {
        X509Certificate cert = getCertificate(alias)
                .orElseThrow(() -> new IllegalArgumentException("No such certificate alias " + alias));

        Base64.Encoder toBase64 = Base64.getMimeEncoder(64, new byte[]{'\n'});
        try (BufferedWriter pem = new BufferedWriter(new OutputStreamWriter(pemStream, StandardCharsets.US_ASCII))) {
            pem.write("-----BEGIN CERTIFICATE-----\n");
            pem.write(toBase64.encodeToString(cert.getEncoded()));
            pem.write('\n');
            pem.write("-----END CERTIFICATE-----\n");
        } catch (CertificateException ex) {
            logger.log(Level.WARNING, "Security failure exporting certificate", ex);
            throw new IOException("Security failure exporting certificate", ex);
        }
    }

    /**
     * Add or replace the provided certificate in the key store using the
     * provided alias
     *
     * @param alias The alias for the key and cert
     * @param cert  The certificate to be added
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if the certificate cannot be added
     * @throws NullPointerException       if alias or cert are null
     */
    public void set(@NonNull String alias, @NonNull X509Certificate cert) throws KeyStoreDestroyedException, IOException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }
        try {
            keystore.setCertificateEntry(Objects.requireNonNull(alias, "alias"), Objects.requireNonNull(cert, "cert"));
        } catch (KeyStoreException ex) {
            logger.log(Level.WARNING, "Failed storing certificate for alias " + alias, ex);
            throw new IOException("Security failure adding certificate", ex);
        }
        if (isPersistent()) {
            store();
        }
    }

    /**
     * Add or replace the provided certificates and key to the key store using
     * an alias calculated from the SHA256 hash of the public key
     *
     * @param key   The key to be added
     * @param certs The certificate to be added
     * @return The alias of the certificate and key
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if the key or certificate cannot be added
     * @throws NullPointerException       if certs or key are null
     */
    public @NonNull String set(PrivateKey key, @NonNull X509Certificate[] certs) throws KeyStoreDestroyedException, IOException {
        if (Objects.requireNonNull(certs, "certs").length < 1) {
            throw new IllegalArgumentException("Must provide at least one certificate");
        }
        String alias = toAlias(certs[0].getPublicKey());
        set(alias, Objects.requireNonNull(key, "key"), certs);
        return alias;
    }

    /**
     * Add or replace the provided certificates and key to the key store using
     * the provided alias
     *
     * @param alias The alias for the key and cert
     * @param key   The key to be added
     * @param certs The certificate to be added
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if the key or certificate cannot be added
     * @throws NullPointerException       if alias, key or certs is null
     */
    public void set(@NonNull String alias, @NonNull PrivateKey key, X509Certificate @NonNull[] certs) throws KeyStoreDestroyedException, IOException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }
        if (Objects.requireNonNull(certs, "certs").length < 1) {
            throw new IllegalArgumentException("Must provide at least one certificate");
        }
        char [] keyPass = null;
        try {
            keyPass = keyPassword.apply(Objects.requireNonNull(alias, "alias"));
            keystore.setKeyEntry(alias, Objects.requireNonNull(key, "key"), keyPass, certs);
        } catch (KeyStoreException | IllegalArgumentException ex) {
            logger.log(Level.WARNING, "Failed storing key for alias " + alias, ex);
            throw new IOException("Security failure adding key", ex);
        } finally {
            if (null != keyPass) {
                Arrays.fill(keyPass, (char) 0);
            }
        }
        if (isPersistent()) {
            store();
        }
    }

    /**
     * Generate an RSA key pair and set the resulting private key and
     * self-signed certificate in the key store
     *
     * @param subjectDN The certificate X.500 subject distinguished name
     * @return The alias of the generated certificate and key
     * @throws IllegalArgumentException   if the provided subject distinguished
     *                                    name is invalid
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if key/certificate generation fails or adding fails
     * @throws NullPointerException       if subjectDN is null
     */
    public @NonNull String generate(@NonNull String subjectDN) throws KeyStoreDestroyedException, IllegalArgumentException, IOException {
        return generate(new X500Principal(Objects.requireNonNull(subjectDN, "subjectDN")));
    }

    /**
     * Generate an RSA key pair and set the resulting private key and
     * self-signed certificate in the key store
     *
     * @param subjectDN The certificate X.500 subject distinguished name
     * @return The alias of the generated certificate and key
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws IOException                if key/certificate generation fails or adding fails
     * @throws NullPointerException       if subjectDN is null
     */
    public @NonNull String generate(@NonNull X500Principal subjectDN) throws KeyStoreDestroyedException, IOException {
        return generate(subjectDN, (X509Certificate[]) null, null);
    }

    /**
     * Generate an RSA key pair and set the resulting private key and
     * signed certificate in the key store along with issuer certificate
     *
     * @param subjectDN  The certificate X.500 subject distinguished name
     * @param issuerCert The certificate of the issuer or null for self-signed
     * @param issuerKey  The private signing key of issuer or null for self-signed
     * @return The alias of the generated certificate and key
     * @throws IOException                if key/certificate generation fails or adding fails
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws NullPointerException       if subjectDN is null or only one of
     *                                    issuerCert and issuerKey is null
     */
    public @NonNull String generate(@NonNull X500Principal subjectDN, @Nullable X509Certificate issuerCert, PrivateKey issuerKey) throws KeyStoreDestroyedException, IOException {
        return generate(subjectDN, null != issuerCert ? new X509Certificate[]{issuerCert} : null, issuerKey);
    }

    /**
     * Generate an RSA key pair and set the resulting private key and
     * signed certificate in the key store along with issuer certificates
     *
     * @param subjectDN   The certificate X.500 subject distinguished name
     * @param issuerCerts The certificates of the issuer or null for self-signed
     * @param issuerKey   The private signing key of issuer or null for self-signed
     * @return The alias of the generated certificate and key
     * @throws IOException                if key/certificate generation fails or adding fails
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     */
    public @NonNull String generate(@NonNull X500Principal subjectDN, X509Certificate @Nullable [] issuerCerts, @Nullable PrivateKey issuerKey) throws KeyStoreDestroyedException, IOException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }

        PrivateKey key;
        X509Certificate cert;
        try {
            SecureRandom secureRandom = secureRandomSupplier.get();
            KeyPairGenerator keyGen = null != provider
                    ? KeyPairGenerator.getInstance("RSA", provider)
                    : KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(RSA_KEY_SIZE, secureRandom);
            KeyPair pair = keyGen.generateKeyPair();

            key = pair.getPrivate();

            X500Principal issuerDN;
            if (null == issuerCerts && null == issuerKey) {
                // self signed
                issuerDN = Objects.requireNonNull(subjectDN, "subjectDN");
                issuerKey = key;
            } else {
                // issuer signed
                if (Objects.requireNonNull(issuerCerts, "issuerCerts").length < 1) {
                    throw new IllegalArgumentException("Empty issuer certs");
                }
                issuerDN = Objects.requireNonNull(Objects.requireNonNull(issuerCerts[0], "issuerCerts[0]").getSubjectX500Principal(), "issuerCerts[0].getSubjectX500Principal");
                issuerKey = Objects.requireNonNull(issuerKey, "issuerKey");
            }

            ZonedDateTime now = ZonedDateTime.now();

            var certBuilder = new JcaX509v1CertificateBuilder(
                    issuerDN,
                    BigInteger.valueOf(now.toInstant().toEpochMilli()), //serial number
                    Date.from(now.minus(MAX_CLOCK_DRIFT).toInstant()),
                    Date.from(now.plus(CERTIFICATE_CRYPTO_PERIOD).toInstant()),
                    Objects.requireNonNull(subjectDN, "subjectDN"),
                    pair.getPublic());

            var signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
            if (null != provider) {
                signerBuilder.setProvider(provider);
            }
            var converter = new JcaX509CertificateConverter();
            if (null != provider) {
                converter.setProvider(provider);
            }
            cert = converter.getCertificate(certBuilder.build(signerBuilder.build(issuerKey)));
        } catch (GeneralSecurityException | IllegalArgumentException | NullPointerException | SecurityException |
                 OperatorCreationException ex) {
            logger.log(Level.WARNING, "Key/Certificate generation failed", ex);
            throw new IOException("Key/Certificate generation failed", ex);
        }
        try {
            X509Certificate[] certChain = null == issuerCerts
                    ? new X509Certificate[]{cert}
                    : Stream.concat(Stream.of(cert), Stream.of(issuerCerts)).toArray(X509Certificate[]::new);
            // The generated key is not "precious" until we save it.
            return set(key, certChain);
        } finally {
            try {
                key.destroy();
            } catch (DestroyFailedException ex) {
                // ignore due to JDK-8160206
            }
        }
    }

    /**
     * Returns true if the provided alias has an associated certificate
     *
     * @param alias The alias
     * @return true if the provided alias has an associated certificate
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws NullPointerException       if alias is null
     */
    public boolean hasCertificate(String alias)
            throws KeyStoreDestroyedException, NullPointerException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }

        try {
            return keystore.isCertificateEntry(Objects.requireNonNull(alias, "alias")) || keystore.isKeyEntry(alias);
        } catch (KeyStoreException ex) {
            logger.log(Level.WARNING, "Failed reading certificate", ex);
        }

        return false;
    }

    /**
     * Retrieve the certificate for the specified alias from the key store
     *
     * @param alias the desired alias
     * @return If present, the certificate for the specified alias or if absent
     * then no certificate is available for the specified alias
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws NullPointerException       if alias is null
     */
    public @NonNull Optional<X509Certificate> getCertificate(@NonNull String alias)
            throws KeyStoreDestroyedException, NullPointerException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }

        try {
            Certificate cert = keystore.getCertificate(Objects.requireNonNull(alias, "alias"));
            if (cert instanceof X509Certificate) {
                return Optional.of((X509Certificate) cert);
            } else if (null != cert) {
                logger.log(Level.WARNING, alias + " mapped to inappropriate certificate", cert);
            } else {
                logger.log(Level.WARNING, "certificate not found", alias);
            }
        } catch (KeyStoreException ex) {
            logger.log(Level.WARNING, "Security failure getting alias " + alias, ex);
        }
        return Optional.empty();
    }

    /**
     * Returns true if the provided alias has an associated key and certificate
     *
     * @param alias The alias
     * @return true if the provided alias has an associated key and certificate
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws NullPointerException       if alias is null
     */
    public boolean hasKey(String alias)
            throws KeyStoreDestroyedException, NullPointerException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }

        try {
            return hasCertificate(alias) && keystore.isKeyEntry(alias);
        } catch (KeyStoreException ex) {
            logger.log(Level.WARNING, "Security failure checking alias " + alias, ex);
        }

        return false;
    }

    /**
     * Retrieve the key pair for the specified alias from the key store
     *
     * @param alias the desired alias
     * @return If present, the key pair for the specified alias or if absent
     * then no key pair is available for the specified alias or key password is
     * not available for specified alias
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws NullPointerException       if alias is null
     */
    public @NonNull Optional<KeyPair> getKey(@NonNull String alias)
            throws KeyStoreDestroyedException, NullPointerException {
        if (!hasKey(alias)) {
            logger.finer(alias + " has no key entry");
            return Optional.empty();
        }

        return getCertificate(alias).map(X509Certificate::getPublicKey)
                .map((PublicKey publicKey) -> {
                    try {
                        char [] keyPass;
                        try {
                            keyPass = keyPassword.apply(Objects.requireNonNull(alias, "alias"));
                        } catch (IllegalArgumentException noKey) {
                            logger.log(Level.WARNING, alias, "not recognized, no key password");
                            return null;
                        }

                        Key privateKey;
                        try {
                            privateKey = keystore.getKey(alias, keyPass);
                        } finally {
                            if (null != keyPass) {
                                Arrays.fill(keyPass, (char) 0);
                            }
                        }
                        if (privateKey instanceof PrivateKey) {
                            return new KeyPair(publicKey, (PrivateKey) privateKey);
                        } else if (null != privateKey) {
                            logger.log(Level.WARNING, alias + " mapped to inappropriate key material:", privateKey);
                        } else {
                            logger.log(Level.WARNING, alias, "key not found");
                        }
                    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
                        logger.log(Level.WARNING, alias + " Failed reading key", ex);
                    }
                    return null;
                });
    }

    /**
     * Remove the key pair and/or certificate for the specified alias from the key store
     *
     * @param alias the desired alias to be removed
     * @return true if the alias was removed otherwise false
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     * @throws java.io.IOException        If removal fails
     * @throws NullPointerException       if alias is null
     */
    public boolean remove(String alias)
            throws KeyStoreDestroyedException, IOException, NullPointerException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }
        try {
            keystore.deleteEntry(Objects.requireNonNull(alias, "alias"));
        } catch (KeyStoreException ex) {
            logger.log(Level.WARNING, "Failed removing alias " + alias, ex);
            return false;
        }
        if (isPersistent()) {
            store();
        }
        return true;
    }

    /**
     * Returns the count of available aliases in the key store
     *
     * @return the count of available aliases in the key store or -1 if the
     * size cannot be determined
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     */
    public int size() throws KeyStoreDestroyedException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }
        try {
            return keystore.size();
        } catch (KeyStoreException ex) {
            logger.log(Level.WARNING, "Failed getting key store size", ex);
            return -1;
        }
    }

    /**
     * Returns a stream of all the aliases in the key store
     *
     * @return a stream of all the aliases in the key store
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     */
    public @NonNull Stream<String> aliases() throws KeyStoreDestroyedException {
        if (isDestroyed()) {
            throw new KeyStoreDestroyedException();
        }
        try {
            return Collections.list(keystore.aliases()).stream();
        } catch (KeyStoreException ex) {
            logger.log(Level.WARNING, "Security failure reading keystore", ex);
            return Stream.empty();
        }
    }

    /**
     * Returns a stream of all the certificate aliases in the key store
     *
     * @return a stream of all the certificate aliases in the key store
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     */
    public Stream<String> certificates() throws KeyStoreDestroyedException {
        return aliases()
                .filter(this::hasCertificate);
    }

    /**
     * Returns a stream of all the key aliases in the key store
     *
     * @return a stream of all the key aliases in the key store
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     */
    public Stream<String> keys() throws KeyStoreDestroyedException {
        return aliases()
                .filter(this::hasKey);
    }

    /**
     * Returns the associated key pair for the provided alias
     *
     * @param alias The key alias of the desired key pair
     * @return The associated key pair
     * @throws AliasNotFoundException     if no key pair is available for the
     *                                    specified alias
     * @throws NullPointerException       if the provided alias is null
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     */
    public KeyPair keyMapper(@NonNull String alias) throws KeyStoreDestroyedException, AliasNotFoundException {
        logger.finer("reading private key for alias " + alias);
        Optional<KeyPair> priv = getKey(alias);
        return priv.orElseThrow(() -> {
            logger.log(Level.WARNING, "No private key found for alias " + alias);
            return new AliasNotFoundException("No private key found", alias);
        });
    }

    /**
     * Returns the associated certificate for the provided alias
     *
     * @param alias The certificate alias of the desired certificate
     * @return The associated certificate
     * @throws AliasNotFoundException     if no certificate is available for the
     *                                    specified alias
     * @throws NullPointerException       if the provided alias is null
     * @throws KeyStoreDestroyedException if the key store has been destroyed
     */
    public X509Certificate certificateMapper(@NonNull String alias) throws KeyStoreDestroyedException, AliasNotFoundException {
        logger.finer("reading certificate for alias " + alias);
        Optional<X509Certificate> pub = getCertificate(alias);
        return pub.orElseThrow(() -> {
            logger.log(Level.WARNING, "No certificate found for alias", alias);
            return new AliasNotFoundException("No certificate found", alias);
        });
    }

    /**
     * Forcible reloads the keystore following potential external modification.
     * Does nothing if the keystore is not persistent.
     *
     * @throws KeyStoreDestroyedException if the keystore has already been
     *                                    destroyed
     * @throws IOException                for errors reading the keystore
     * @implSpec Reloading the keystore may make existing key and certificate
     * instances previously provided by this instance unusable. It is difficult
     * or impossible to use this method correctly in a complex multi-threaded
     * environment. You have been warned.
     */
    public void reload() throws KeyStoreDestroyedException, IOException {
        if (isPersistent()) {
            load();
        }
    }

    /**
     * Loads the key store from the standard location
     *
     * @throws IOException                   if loading the key store fails
     * @throws UnsupportedOperationException if the keystore is not persistent
     * @throws KeyStoreDestroyedException    if the key store has been destroyed
     */
    protected void load() throws KeyStoreDestroyedException, UnsupportedOperationException, IOException {
        if (!isPersistent()) {
            throw new UnsupportedOperationException("keystore is not persistent");
        }
        // copy field to local to avoid race conditions
        char[] storePass = storePassword;
        storePass = null != storePass ? Arrays.copyOf(storePass, storePass.length) : null;
        if (DESTROYED == storePassword) {
            if (null != storePass) {
                Arrays.fill(storePass, (char) 0);
            }
            throw new KeyStoreDestroyedException();
        }
        try (InputStream input = openInput(location)) {
            keystore.load(null != input ? new BufferedInputStream(input) : null, storePass);
            logger.info("Read keystore " + location + " size=" + size());
        } catch (NoSuchAlgorithmException | CertificateException ex) {
            logger.log(Level.WARNING, "Security failure reading keystore", ex);
            throw new IOException("Security failure reading keystore", ex);
        } finally {
            if (null != storePass) {
                Arrays.fill(storePass, (char) 0);
            }
        }
    }

    /**
     * Persists the key store to the specified location
     *
     * @throws IOException                   if persisting the key store fails
     * @throws UnsupportedOperationException if the keystore is not persistent
     * @throws KeyStoreDestroyedException    if the key store has been destroyed
     */
    protected void store() throws KeyStoreDestroyedException, UnsupportedOperationException, IOException {
        if (!isPersistent()) {
            throw new UnsupportedOperationException("keystore is not persistent");
        }
        // copy field to local to avoid race conditions
        char[] storePass = storePassword;
        storePass = null != storePass ? Arrays.copyOf(storePass, storePass.length) : null;
        if (DESTROYED == storePassword) {
            if (null != storePass) {
                Arrays.fill(storePass, (char) 0);
            }
            throw new KeyStoreDestroyedException();
        }
        try (OutputStream output = new BufferedOutputStream(openOutput(location))) {
            keystore.store(output, storePass);
            logger.info("Wrote keystore " + location + " size=" + size());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            logger.log(Level.WARNING, "Security failure writing keystore", ex);
            throw new IOException("Security failure writing keystore", ex);
        } finally {
            if (null != storePass) {
                Arrays.fill(storePass, (char) 0);
            }
        }
    }

    /**
     * Utility method for converting key to alias
     *
     * @param key The key
     * @return the alias, the SHA256 hash of the key as a hexadecimal string
     */
    protected @NonNull String toAlias(@NonNull Key key) {
        MessageDigest sha256;
        try {
            sha256 = null != provider ? MessageDigest.getInstance("SHA-256", provider) : MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new InternalError("SHA256 Message Digest unavailable.", ex);
        }
        byte[] keyEncoded = key.getEncoded();
        byte[] keyEncodedHash = sha256.digest(keyEncoded);
        Arrays.fill(keyEncoded, (byte) 0);
        return toHexString(keyEncodedHash);
    }

    /**
     * Function mapping key alias to the key password
     */
    public interface PasswordMapper extends Function<String, char[]> {
        /**
         * Function mapping key alias to the key password
         *
         * @throws IllegalArgumentException if key alias is not recognized
         * @throws NullPointerException     if key alias is null
         */
        @Override
        char @Nullable [] apply(@NonNull String s);
    }

    /**
     * The key store has already been destroyed
     */
    public static class KeyStoreDestroyedException extends IllegalStateException {

        public KeyStoreDestroyedException() {
            this(null);
        }

        public KeyStoreDestroyedException(@Nullable Throwable cause) {
            this("key store already destroyed", cause);
        }

        public KeyStoreDestroyedException(String message, @Nullable Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * The specified alias was not found
     */
    public static class AliasNotFoundException extends IllegalArgumentException {

        /**
         * The alias which was not found
         */
        @NonNull
        public final String alias;

        public AliasNotFoundException(String message, @NonNull String alias) {
            this(message, alias, null);
        }

        public AliasNotFoundException(String message, @NonNull String alias, @Nullable Throwable cause) {
            super(message + ": " + alias, cause);
            this.alias = alias;
        }
    }
}
