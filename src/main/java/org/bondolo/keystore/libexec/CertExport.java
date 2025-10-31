/*
 */
package org.bondolo.keystore.libexec;

import org.bondolo.keystore.BCHolder;
import org.bondolo.keystore.KeyStoreContainer;
import org.jspecify.annotations.NonNull;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.bondolo.keystore.BCHolder.BC;
import static org.bondolo.keystore.Passwords.KEY_PASSWORD;
import static org.bondolo.keystore.Passwords.STORE_PASSWORD;

/**
 * Exports trusted certificates
 */
@SuppressWarnings("UseOfSystemOutOrSystemErr")
public class CertExport {

    protected static final Logger LOGGER = Logger.getLogger(CertExport.class.getSimpleName());

    /**
     * Exports trusted certificates for use with Secure Logging.
     *
     * @param args The command line arguments
     * @throws Throwable Thrown for various failures
     */
    public static void main(String @NonNull ... args) throws Throwable {
        Thread.currentThread().setName(CertExport.class.getSimpleName() + ".main");
        if (args.length != 3) {
            System.err.println("Insufficient arguments: CertExport <alias> <trustfile> <pemfile>");
            System.err.println("alias      the certificate to export");
            System.err.println("trustfile  trust store file path");
            System.err.println("pemfile    certificate pem file path");
            System.exit(1);
        }

        String alias = args[0];
        Path trustPath = Paths.get(args[1]);
        Path pemPath = Paths.get(args[2]);

        if (null == BCHolder.BC) {
            System.err.println("Cryptography provider not available");
            System.exit(1);
        }

        KeyStoreContainer truststore = new KeyStoreContainer(
                KeyStore.getInstance("PKCS12", BCHolder.BC),
                trustPath,
                STORE_PASSWORD,
                (_) -> Arrays.copyOf(KEY_PASSWORD, KEY_PASSWORD.length),
                BC,
                () -> {
                    try {
                        return SecureRandom.getInstance("DEFAULT", BC);
                    } catch (NoSuchAlgorithmException e) {
                        throw new SecurityException(e);
                    }
                });
        truststore.exportPEM(alias, pemPath);
        LOGGER.info("Exported certificate " + alias + " to " + pemPath);
    }
}
