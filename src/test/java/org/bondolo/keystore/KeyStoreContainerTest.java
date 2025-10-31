/*
 */
package org.bondolo.keystore;

import org.bondolo.keystore.KeyStoreContainer.KeyStoreDestroyedException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Basic tests of KeyStoreContainer
 */
public class KeyStoreContainerTest implements TestWatcher {

    protected static final char[] STORE_PASSWORD = "changeit".toCharArray();
    protected static final char[] KEY_PASSWORD = "changeit".toCharArray();
    protected static final String CLIENT_ALIAS = "7567250ff0050bf1ed16929efd196dc54d9bc839804ee6e4975e60bc9826c98d";
    protected static final String SERVER_ALIAS = "fd573a0121c5dcf215de58613efe753850ca7a9a2c788bbda6ede77ee0840e47";

    private static final Logger LOGGER = Logger.getLogger(KeyStoreContainerTest.class.getSimpleName());
    private static final KeyStoreContainer.PasswordMapper KEY_PASSWORDS = (_) -> Arrays.copyOf(KEY_PASSWORD, KEY_PASSWORD.length);
    private static final String ALIAS = SERVER_ALIAS;
    private Path keystoreLocation;

    private static @NonNull Stream<Arguments> providers() {
        assertNotNull(BCHolder.BC);
        return Stream.of(
                Arguments.of(BCHolder.BC, (Supplier<SecureRandom>) () -> {
                    try {
                        return SecureRandom.getInstance("DEFAULT", BCHolder.BC);
                    } catch (NoSuchAlgorithmException e) {
                        throw new SecurityException(e);
                    }
                }),
                Arguments.of(null, (Supplier<SecureRandom>) SecureRandom::new)
        );
    }

    @Override
    public void testSuccessful(@NonNull ExtensionContext context) {
        LOGGER.info("Starting test: " + context.getDisplayName());
    }

    @BeforeEach
    public void setup() throws Throwable {
        Path tempDir = Files.createTempDirectory(KeyStoreContainerTest.class.getSimpleName());
        keystoreLocation = tempDir.resolve("keystore.p12");
        InputStream server = KeyStoreContainerTest.class.getResourceAsStream("server.p12");
        assertNotNull(server);
        Files.copy(server, keystoreLocation);
    }

    /**
     * Test of destroy and isDestroyed methods, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testDestroy(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        assertFalse(instance.isDestroyed());
        instance.destroy();
        assertTrue(instance.isDestroyed());
    }

    /**
     * Test of destroy and isDestroyed methods, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testDestroyThrow(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        assertFalse(instance.isDestroyed());
        instance.destroy();
        assertThrows(KeyStoreDestroyedException.class, () -> instance.getCertificate(ALIAS));
    }

    /**
     * Test of set method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testAddCertificate(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        Optional<X509Certificate> cert = instance.getCertificate(ALIAS);
        assertTrue(cert.isPresent());
        assertTrue(instance.remove(ALIAS));
        assertFalse(instance.getCertificate(ALIAS).isPresent());
        String added = instance.set(cert.get());
        assertEquals(ALIAS, added);
        assertTrue(instance.getCertificate(ALIAS).isPresent());
    }

    /**
     * Test of set method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testAddKey(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        URI storeURI = keystoreLocation.toUri();
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), storeURI,
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        assertTrue(instance.isPersistent());
        assertTrue(instance.location().isPresent());
        assertEquals(storeURI, instance.location().get());
        Optional<KeyPair> key = instance.getKey(ALIAS);
        Optional<X509Certificate> cert = instance.getCertificate(ALIAS);
        assertTrue(key.isPresent());
        assertTrue(cert.isPresent());
        int size = instance.size();
        assertTrue(instance.remove(ALIAS));
        assertFalse(instance.getCertificate(ALIAS).isPresent());
        assertFalse(instance.getKey(ALIAS).isPresent());
        int newsize = instance.size();
        assertTrue(newsize <= size);
        size = instance.size();
        String added = instance.set(key.get().getPrivate(), new X509Certificate[]{cert.get()});
        assertEquals(ALIAS, added);
        assertTrue(instance.getCertificate(ALIAS).isPresent());
        assertTrue(instance.getKey(ALIAS).isPresent());
        newsize = instance.size();
        assertTrue(newsize >= size);
    }

    @ParameterizedTest
    @MethodSource("providers")
    public void testGenerate(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);

        String selfSigned = instance.generate("UID=1, CN=self, EMAILADDRESS=support@example.com, ST=California, L=Pasadena, O=Example Corporation, C=US");
        Optional<X509Certificate> cert = instance.getCertificate(selfSigned);
        Optional<KeyPair> key = instance.getKey(selfSigned);
        assertTrue(cert.isPresent());
        assertTrue(key.isPresent());
        X500Principal subjectDN = new X500Principal("UID=2, CN=issued, EMAILADDRESS=support@example.com, ST=California, L=Pasadena, O=Example Corporation, C=US");
        String issused = instance.generate(subjectDN, cert.get(), key.get().getPrivate());
        cert = instance.getCertificate(issused);
        key = instance.getKey(issused);
        assertTrue(cert.isPresent());
        assertTrue(key.isPresent());
    }

    /**
     * Test of getCertificate method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testGetCertificate(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        Optional<X509Certificate> result = instance.getCertificate(ALIAS);
        assertTrue(result.isPresent());
    }

    /**
     * Test of certificateMapper method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testcertificateMapper(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        X509Certificate result = instance.certificateMapper(ALIAS);
        assertNotNull(result);
    }

    /**
     * Test of certificateMapper method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testcertificateMapperBogus(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        KeyStoreContainer.AliasNotFoundException thrown =
                assertThrows(KeyStoreContainer.AliasNotFoundException.class, () -> instance.certificateMapper("bogus"));
        assertEquals("bogus", thrown.alias);
    }

    /**
     * Test of certificateMapper method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testcertificateMapperNull(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        //noinspection DataFlowIssue
        assertThrows(NullPointerException.class, () -> instance.certificateMapper(null));
    }

    /**
     * Test of getKey method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testGetKey(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        Optional<KeyPair> result = instance.getKey(ALIAS);
        assertTrue(result.isPresent());
    }

    /**
     * Test of certificateMapper method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testKeyMapper(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        KeyPair result = instance.keyMapper(ALIAS);
        assertNotNull(result);
    }

    /**
     * Test of certificateMapper method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testKeyMapperBogus(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        KeyStoreContainer.AliasNotFoundException thrown =
                assertThrows(KeyStoreContainer.AliasNotFoundException.class, () -> instance.keyMapper("bogus"));
        assertEquals("bogus", thrown.alias);
    }

    /**
     * Test of certificateMapper method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testKeyMapperNull(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        //noinspection DataFlowIssue
        assertThrows(NullPointerException.class, () -> instance.keyMapper(null));
    }

    /**
     * Test of remove method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testRemove(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        boolean expResult = true;
        boolean result = instance.remove(ALIAS);
        assertEquals(expResult, result);
    }

    /**
     * Test of aliases method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testAliases(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        instance.aliases()
                .filter(ALIAS::equals)
                .findAny()
                .orElseThrow(() -> new AssertionError("Missing expected alias"));
    }

    /**
     * Test of certificates method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testCertificates(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        instance.certificates()
                .filter(ALIAS::equals)
                .findAny()
                .orElseThrow(() -> new AssertionError("Missing expected alias"));
    }

    /**
     * Test of keys method, of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testKeys(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        instance.keys()
                .filter(ALIAS::equals)
                .findAny()
                .orElseThrow(() -> new AssertionError("Missing expected alias"));
    }

    @ParameterizedTest
    @MethodSource("providers")
    public void testReadOnly(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Objects.requireNonNull(KeyStoreContainerTest.class.getResource("client.p12")).toURI(), true,
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);

        assertFalse(instance.isPersistent());
    }

    @ParameterizedTest
    @MethodSource("providers")
    public void testInitialize(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                null, keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        int size = instance.size();
        assertEquals(0, size);
    }

    @ParameterizedTest
    @MethodSource("providers")
    public void testReload(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);

        instance.reload();
    }

    /**
     * Test of importPEM(URI), of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testImportPEMuri(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        String importAlias = CLIENT_ALIAS;
        URI pemFile = Paths.get("src/test/resources/org/bondolo/keystore/" + importAlias + ".pem").toUri();
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        assertFalse(instance.hasCertificate(importAlias));
        var resultAlias = instance.importPEM(pemFile);
        assertEquals(importAlias, resultAlias);
        assertTrue(instance.hasCertificate(importAlias));
    }

    /**
     * Test of importPEM(Path), of class KeyStoreContainer.
     */
    @ParameterizedTest
    @MethodSource("providers")
    public void testImportPEMpath(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        String importAlias = CLIENT_ALIAS;
        Path pemFile = Paths.get("src/test/resources/org/bondolo/keystore/" + importAlias + ".pem");
        KeyStore keyStore = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        KeyStoreContainer instance = new KeyStoreContainer(keyStore,
                Files.newInputStream(keystoreLocation), keystoreLocation.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        assertFalse(instance.hasCertificate(importAlias));
        instance.importPEM(pemFile);
        assertTrue(instance.hasCertificate(importAlias));
    }

    @ParameterizedTest
    @MethodSource("providers")
    public void testExportAndImport(@Nullable Provider provider, @NonNull Supplier<SecureRandom> secureRandomSupplier) throws Throwable {
        // Create a new keystore and generate a key and cert
        KeyStore keyStore1 = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        Path tempDir = Files.createTempDirectory(KeyStoreContainerTest.class.getSimpleName());
        Path keystoreLocation1 = tempDir.resolve("keystore1.p12");
        KeyStoreContainer instance1 = new KeyStoreContainer(keyStore1,
                null, keystoreLocation1.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        String alias = instance1.generate("CN=Test");
        Optional<X509Certificate> cert1 = instance1.getCertificate(alias);
        assertTrue(cert1.isPresent());

        // Export the cert
        Path certFile = tempDir.resolve("cert.pem");
        instance1.exportPEM(alias, certFile);
        assertTrue(Files.exists(certFile));

        // Create a second keystore and import the cert
        KeyStore keyStore2 = null != provider ? KeyStore.getInstance("PKCS12", provider) : KeyStore.getInstance("PKCS12");
        Path keystoreLocation2 = tempDir.resolve("keystore2.p12");
        KeyStoreContainer instance2 = new KeyStoreContainer(keyStore2,
                null, keystoreLocation2.toUri(),
                STORE_PASSWORD,
                KEY_PASSWORDS, provider, secureRandomSupplier);
        assertFalse(instance2.hasCertificate(alias));
        instance2.importPEM(certFile);
        Optional<X509Certificate> cert2 = instance2.getCertificate(alias);
        assertTrue(cert2.isPresent());
        assertEquals(cert1.get(), cert2.get());
    }
}
