/*
 */
package org.bondolo.keystore.libexec;

import org.bondolo.keystore.BCHolder;
import org.bondolo.keystore.KeyStoreContainer;
import org.jspecify.annotations.NonNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.bondolo.keystore.Passwords.KEY_PASSWORD;
import static org.bondolo.keystore.Passwords.STORE_PASSWORD;

/**
 * Lists the certificates and keys stored in a key or trust store
 */
@SuppressWarnings("UseOfSystemOutOrSystemErr")
public class StoreList {

    protected static final Logger LOGGER = Logger.getLogger(StoreList.class.getSimpleName());

    private static @NonNull String toAlias(@NonNull Key key) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", Objects.requireNonNull(BCHolder.BC));
        byte[] keyEncoded = key.getEncoded();
        byte[] keyEncodedHash = sha256.digest(keyEncoded);
        Arrays.fill(keyEncoded, (byte) 0);
        StringBuilder alias = new StringBuilder(keyEncodedHash.length * 2);
        for (byte b : keyEncodedHash) {
            alias.append(String.format("%02x", b));
        }
        return alias.toString();
    }

    /**
     * Lists the certificates and keys stored in a key or trust store
     *
     * @param args The command line arguments
     * @throws Throwable Thrown for various failures
     */
    public static void main(String @NonNull ... args) throws Throwable {
        Thread.currentThread().setName(CertImport.class.getSimpleName() + ".main");

        if (args.length != 1) {
            System.err.println("Insufficient arguments: StoreList <keysfile|trustfile> ");
            System.err.println("keysfile   key store file path");
            System.err.println("trustfile  trust store file path");
            System.exit(1);
            return;
        }

        Path storePath = Paths.get(args[0]);

        if (!Files.isReadable(storePath)) {
            LOGGER.warning("Unable to read store from path " + storePath);
            System.exit(1);
            return;
        }

        if (null == BCHolder.BC) {
            System.err.println("Cryptography provider not available");
            System.exit(1);
        }

        KeyStoreContainer store;
        try {
            store = new KeyStoreContainer(
                    KeyStore.getInstance("PKCS12", BCHolder.BC),
                    storePath,
                    STORE_PASSWORD,
                    (_) -> Arrays.copyOf(KEY_PASSWORD, KEY_PASSWORD.length),
                    BCHolder.BC,
                    () -> {
                        try {
                            return SecureRandom.getInstance("DEFAULT", BCHolder.BC);
                        } catch (NoSuchAlgorithmException e) {
                            throw new SecurityException(e);
                        }
                    });
        } catch (KeyStoreException ex) {
            LOGGER.log(Level.WARNING, "Provider Failure " + storePath, ex);
            System.exit(1);
            return;
        }

        store.aliases().forEach(alias -> StoreList.printAlias(store, alias));
    }

    static void printAlias(@NonNull KeyStoreContainer store, @NonNull String alias) {
        Optional<X509Certificate> cert = store.getCertificate(alias);

        boolean correctAlias = false;
        if (cert.isPresent()) try {
            String calcAlias = toAlias(cert.get().getPublicKey());
            correctAlias = alias.equals(calcAlias);
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, alias, ex);
        }

        Optional<KeyPair> keys = store.getKey(alias);

        // cert         : null or a certificate
        // correctAlias : boolean
        // hasPrivate   : boolean
        String descriptor = cert.isPresent()
                ? keys.isPresent()
                ? "KEYPAIR     "
                : "CERTIFICATE "
                : keys.isPresent()
                ? "KEYONLY     "
                : "BOGUS       ";

        System.out.println(descriptor + (correctAlias ? "    " : "(*) ") + alias);
        cert.ifPresent(certificate -> System.out.println("\tsubject=<" + certificate.getSubjectX500Principal() + ">"));
    }
}
