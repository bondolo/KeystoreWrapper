/*
 */
package org.bondolo.keystore.libexec;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KeyGen
 */
public class KeyGenTest {

    static @NonNull Stream<Arguments> data() {
        return Arrays.stream(new Arguments[]{
                        Arguments.of("cn=fred, uid=0"),
                        Arguments.of("cn=barney, uid=18675309")
                }
        );
    }

    /**
     * Test of main method, of class KeyGen.
     *
     */
    @ParameterizedTest
    @MethodSource("data")
    public void testMain(String subjectDN) throws Throwable {
        Path storeFile = Files.createTempFile(KeyGenTest.class.getSimpleName(), ".p12");
        Files.delete(storeFile);
        Path pemFile = Files.createTempFile(KeyGenTest.class.getSimpleName(), ".pem");
        Files.delete(pemFile);

        String[] args = new String[]{subjectDN, pemFile.toString(), storeFile.toString()};
        KeyGen.main(args);

        assertTrue(Files.exists(storeFile));
        assertTrue(Files.exists(pemFile));
    }
}
