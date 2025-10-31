module org.bondolo.keystore {
    requires java.base;
    requires java.logging;
    requires org.jspecify;
    requires static org.bouncycastle.provider;
    requires static org.bouncycastle.pkix;

    exports org.bondolo.keystore;
}
