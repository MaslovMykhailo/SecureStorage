package com.mm.securestorage.service.security.crypto;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

public class AwsKmsCrypto {

    private final KmsMasterKeyProvider keyProvider;

    private final AwsCrypto crypto = AwsCrypto
        .builder()
        .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
        .build();

    public AwsKmsCrypto(String awsKmsArn) {
        keyProvider = KmsMasterKeyProvider.builder().buildStrict(awsKmsArn);
    }

    public CryptoResult<byte[], KmsMasterKey> encrypt(byte[] data) {
        return crypto.encryptData(keyProvider, data);
    }

    public CryptoResult<byte[], KmsMasterKey> decrypt(byte[] data) {
        return crypto.decryptData(keyProvider, data);
    }
}
