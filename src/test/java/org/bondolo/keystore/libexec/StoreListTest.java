/*
 */
package org.bondolo.keystore.libexec;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 *
 */
public class StoreListTest {

    static @NonNull Stream<Arguments> data() {
        return Arrays.stream(new Arguments[]{
                Arguments.of(Paths.get("src/test/resources/org/bondolo/keystore/server.p12")),
                Arguments.of(Paths.get("src/test/resources/org/bondolo/keystore/client.p12")),
                Arguments.of(Paths.get("src/test/resources/org/bondolo/keystore/trust.p12"))
        });
    }

    /**
     * Test of main method, of class StoreList.
     *
     */
    @ParameterizedTest
    @MethodSource("data")
    public void testMain(@NonNull Path store) throws Throwable {
        String[] args = new String[]{store.toString()};
        StoreList.main(args);
    }
}
