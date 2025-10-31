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
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CertExport
 */
public class CertExportTest {

    static @NonNull Stream<Arguments> data() {
        return Stream.of(
                Arguments.of("7567250ff0050bf1ed16929efd196dc54d9bc839804ee6e4975e60bc9826c98d", Paths.get("src/test/resources/org/bondolo/keystore/client.p12")),
                Arguments.of("7567250ff0050bf1ed16929efd196dc54d9bc839804ee6e4975e60bc9826c98d", Paths.get("src/test/resources/org/bondolo/keystore/trust.p12")),
                Arguments.of("fd573a0121c5dcf215de58613efe753850ca7a9a2c788bbda6ede77ee0840e47", Paths.get("src/test/resources/org/bondolo/keystore/trust.p12"))
        );
    }

    /**
     * Test of main method, of class CertExport.
     *
     */
    @ParameterizedTest
    @MethodSource("data")
    public void testMain(String alias, @NonNull Path store) throws Throwable {
        assertTrue(Files.isRegularFile(store), "Store not a regular file");
        assertTrue(Files.isReadable(store), "Store not a readable file");

        Path pemFile = Files.createTempFile(CertExportTest.class.getSimpleName(), ".pem");

        String[] args = new String[]{alias, store.toString(), pemFile.toString()};
        CertExport.main(args);

        assertTrue(Files.isRegularFile(pemFile), "pem not a regular file");
        assertTrue(Files.isReadable(pemFile), "pem not a readable file");
        assertTrue(Files.size(pemFile) > 0, "empty pem file");
    }
}
