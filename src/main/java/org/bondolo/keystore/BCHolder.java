/*
 */
package org.bondolo.keystore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jspecify.annotations.Nullable;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Use a holder class to make initialization of bouncy castle lazy.
 */
@SuppressWarnings({"unchecked"})
public class BCHolder {

    /**
     * The bouncy castle Provider or null
     */
    public static final @Nullable Provider BC;
    private static final Logger logger = Logger.getLogger(BCHolder.class.getSimpleName());

    static {
        // Required because we generate keys in the same run as using them
        System.setProperty("org.bouncycastle.rsa.allow_multi_use", "true");

        try {
            int keySize = Cipher.getMaxAllowedKeyLength("AES") >= 256 ? 256 : 128;
            logger.info("Using " + keySize + "bit AES secret keys");
            if (keySize < 256) {
                throw new Error("Unlimited cryptography policy files not installed");
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new Error("Cryptography failure", ex);
        }

        Provider bc;
        try {
            @SuppressWarnings("unchecked")
            var bcProviderClazz = (Class<? extends BouncyCastleProvider>) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");

            // Use installed provider or create Bouncy Castle provider
            Provider installedbc = Security.getProvider("BC");
            bc = bcProviderClazz.isInstance(installedbc)
                    ? installedbc
                    : bcProviderClazz.getDeclaredConstructor().newInstance();
        } catch (Throwable all) {
            logger.log(Level.SEVERE, "Failed initializing bc provider", all);
            bc = null;
        }

        BC = bc;
    }
}
