package com.mm.securestorage.service.security.crypto;

import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.stream.IntStream;

public class EnvelopeCrypto {

    private final AwsKmsCrypto awsKmsCrypto;

    private final AesCrypto aesCrypto;

    public EnvelopeCrypto(AesCrypto aesCrypto, AwsKmsCrypto awsKmsCrypto) {
        this.awsKmsCrypto = awsKmsCrypto;
        this.aesCrypto = aesCrypto;
    }

    public byte[] encrypt(byte[] data) {
        SecretKey key = aesCrypto.generateDataEncryptionKey();

        byte[] encryptedData = aesCrypto.encrypt(data, key);
        byte[] encryptedKey = awsKmsCrypto.encrypt(key.getEncoded()).getResult();

        return ByteBuffer
            .allocate(encryptedData.length + encryptedKey.length)
            .put(encryptedData)
            .put(encryptedKey)
            .array();
    }

    public byte[] decrypt(byte[] data) {
        int ENCRYPTED_KEY_SIZE = 420;

        byte[] encryptedData = ArrayUtils.toPrimitive(
            IntStream
                .range(0, data.length - ENCRYPTED_KEY_SIZE)
                .mapToObj(i -> data[i])
                .toArray(Byte[]::new)
        );

        byte[] encryptedKey = ArrayUtils.toPrimitive(
            IntStream
                .range(data.length - ENCRYPTED_KEY_SIZE, data.length)
                .mapToObj(i -> data[i])
                .toArray(Byte[]::new)
        );

        byte[] key = awsKmsCrypto.decrypt(encryptedKey).getResult();
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        return aesCrypto.decrypt(encryptedData, secretKey);
    }

}
