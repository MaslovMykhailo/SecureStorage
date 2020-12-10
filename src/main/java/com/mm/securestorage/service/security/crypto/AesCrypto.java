package com.mm.securestorage.service.security.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class AesCrypto {

    private final int IV_SIZE = 12;

    private final int KEY_SIZE = 128;

    private static final Logger logger = LoggerFactory.getLogger(AesCrypto.class);

    private final SecureRandom secureRandom = new SecureRandom();

    public SecretKey generateDataEncryptionKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_SIZE, secureRandom);
            return keyGenerator.generateKey();
        } catch (Throwable exception) {
            logger.error("Failed to generate data encryption key", exception);
        }

        return null;
    }

    public byte[] encrypt(byte[] data, SecretKey key) {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(KEY_SIZE, iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] encryptedData = cipher.doFinal(data);

            return ByteBuffer
                .allocate(iv.length + encryptedData.length)
                .put(iv)
                .put(encryptedData)
                .array();
        } catch (Throwable exception) {
            logger.error("Failed to encrypt", exception);
        }

        return null;
    }

    public byte[] decrypt(byte[] data, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(KEY_SIZE, data, 0, IV_SIZE);

            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(data, IV_SIZE, data.length - IV_SIZE);
        } catch (Throwable exception) {
            logger.error("Failed to decrypt", exception);
        }

        return null;
    }

}
