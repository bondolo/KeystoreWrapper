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

import static org.bondolo.keystore.Passwords.KEY_PASSWORD;
import static org.bondolo.keystore.Passwords.STORE_PASSWORD;

/**
 * Imports trusted certificates
 */
@SuppressWarnings("UseOfSystemOutOrSystemErr")
public class CertImport {

    /**
     * Imports trusted certificates
     *
     * @param args The command line arguments
     * @throws Exception Thrown for various failures
     */
    public static void main(String @NonNull ... args) throws Exception {
        Thread.currentThread().setName(CertImport.class.getSimpleName() + ".main");

        if (args.length != 2) {
            System.err.println("Insufficient arguments: CertImport <pemfile> <trustfile> ");
            System.err.println("pemfile    certificate pem file path");
            System.err.println("trustfile  trust store file path");
            System.exit(1);
        }

        Path pemPath = Paths.get(args[0]);
        Path trustPath = Paths.get(args[1]);

        if (null == BCHolder.BC) {
            System.err.println("Cryptography provider not available");
            System.exit(1);
        }

        if (!Files.isWritable(trustPath) && (Files.exists(trustPath) || !Files.isWritable(trustPath.toAbsolutePath().getParent()))) {
            System.err.println("trust file cannot be written " + trustPath);
            System.exit(1);
        }

        KeyStoreContainer truststore = new KeyStoreContainer(
                KeyStore.getInstance("PKCS12", BCHolder.BC),
                trustPath,
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
        String alias = truststore.importPEM(pemPath);
        System.out.println("Added " + alias + " to truststore " + trustPath);
    }
}
