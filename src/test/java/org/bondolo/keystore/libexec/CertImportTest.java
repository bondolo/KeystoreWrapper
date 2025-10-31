/*
 */
package org.bondolo.keystore.libexec;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CertImport
 */
public class CertImportTest {

    static @NonNull Stream<Arguments> data() {
        return Arrays.stream(
                new Arguments[]{
                        Arguments.of("7567250ff0050bf1ed16929efd196dc54d9bc839804ee6e4975e60bc9826c98d", Paths.get("src/test/resources/org/bondolo/keystore/7567250ff0050bf1ed16929efd196dc54d9bc839804ee6e4975e60bc9826c98d.pem")),
                        Arguments.of("fd573a0121c5dcf215de58613efe753850ca7a9a2c788bbda6ede77ee0840e47", Paths.get("src/test/resources/org/bondolo/keystore/fd573a0121c5dcf215de58613efe753850ca7a9a2c788bbda6ede77ee0840e47.pem"))
                });
    }

    /**
     * Test of main method, of class CertImport.
     *
     */
    @ParameterizedTest
    @MethodSource("data")
    public void testMain(String alias, @NonNull Path pemFile) throws Throwable {
        assertTrue(Files.isRegularFile(pemFile), "pemFile not a regular file");
        assertTrue(Files.isReadable(pemFile), "pemFile not a readable file");

        Path storeFile = Files.createTempFile(CertImportTest.class.getSimpleName(), ".p12");
        Files.delete(storeFile);

        String[] args = new String[]{pemFile.toString(), storeFile.toString()};
        CertImport.main(args);

        assertTrue(Files.exists(storeFile));

        String[] listArgs = new String[]{storeFile.toString()};
        StoreList.main(listArgs);
    }
}
