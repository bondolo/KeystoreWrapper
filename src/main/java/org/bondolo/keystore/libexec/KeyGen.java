/*
 */
package org.bondolo.keystore.libexec;

import org.bondolo.keystore.BCHolder;
import org.bondolo.keystore.KeyStoreContainer;
import org.jspecify.annotations.NonNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.bondolo.keystore.Passwords.KEY_PASSWORD;
import static org.bondolo.keystore.Passwords.STORE_PASSWORD;

/**
 * Generates public/private key pairs suitable
 */
@SuppressWarnings("UseOfSystemOutOrSystemErr")
public class KeyGen {
    protected static final Logger LOGGER = Logger.getLogger(KeyGen.class.getSimpleName());

    /**
     * Generates public/private key pairs suitable
     *
     * @param args The command line arguments
     * @throws Throwable Thrown for various failures
     */

    public static void main(String @NonNull ... args) throws Throwable {
        Thread.currentThread().setName(CertImport.class.getSimpleName() + ".main");

        if (args.length < 2) {
            System.err.println("Insufficient arguments: KeyGen <x500dn> <keyfile> [<pemfile>]");
            System.err.println("x500dn     X500 Distinguished Name e.g. 'UID=1, CN=client, EMAILADDRESS=client@example.com, ST=California, L=Pasadena, O=Example Corporation, C=US'");
            System.err.println("keyfile    key store file path eg. keystore.p12");
            System.err.println("pemfile    (optional) certificate pem file path eg. cert.pem");
            System.exit(1);
        }

        String name = args[0];
        Path keyPath = Paths.get(args[1]);

        if (null == BCHolder.BC) {
            System.err.println("Cryptography provider not available");
            System.exit(1);
        }

        if (!Files.isWritable(keyPath) && (Files.exists(keyPath) || !Files.isWritable(keyPath.toAbsolutePath().getParent()))) {
            System.err.println("keystore file cannot be written " + keyPath);
            System.exit(1);
        }

        KeyStoreContainer keyStore = new KeyStoreContainer(
                KeyStore.getInstance("PKCS12", BCHolder.BC),
                keyPath,
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
        String alias = keyStore.generate(name);
        LOGGER.info("Generated " + alias + " for \"" + name + "\"");

        Path pemPath = Paths.get(args.length > 2 ? args[2] : alias + ".pem");

        keyStore.exportPEM(alias, pemPath);
        LOGGER.info("Exported certificate " + alias + "to " + pemPath);
    }
}
