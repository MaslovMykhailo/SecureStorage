#!/bin/sh

LOCAL_CERT_ALIAS=local-cert
SELF_CA_CERT_ALIAS=self-ca-cert

KEY_STORE_P12=./.cert/secure-storage.p12
KEY_STORE_PEM=./.cert/secure-storage.pem
KEY_STORE_CSR=./.cert/secure-storage.csr

SELF_CA_KEY_STORE_P12=./.cert/self-ca.p12
SELF_CA_KEY_STORE_PEM=./.cert/self-ca.pem

KEY_STORE_PASS=password
KEY_PASS=password

keytool -genkeypair \
        -keyalg RSA -keysize 2048 \
        -alias $SELF_CA_CERT_ALIAS \
        -storetype PKCS12 \
        -dname "CN=Mykhailo Maslov self ca cert,C=UA,L=KYIV,O=KPI,OU=FICT" \
        -ext BC:c=ca:true -ext KU=kCS \
        -validity 365 \
        -keystore $SELF_CA_KEY_STORE_P12 \
        -storepass $KEY_STORE_PASS \
        -keypass $KEY_PASS

keytool -exportcert \
        -keystore $SELF_CA_KEY_STORE_P12 \
        -storepass $KEY_STORE_PASS \
        -alias $SELF_CA_CERT_ALIAS \
        -rfc -file $SELF_CA_KEY_STORE_PEM

keytool -genkeypair \
        -keyalg RSA -keysize 2048 \
        -alias $LOCAL_CERT_ALIAS \
        -storetype PKCS12 \
        -dname "CN=Mykhailo Maslov local cert,C=UA,L=KYIV,O=KPI,OU=FICT" \
        -ext BC:c=ca:false \
        -ext EKU:c=serverAuth \
        -ext "SAN:c=DNS:localhost,IP:127.0.0.1" \
        -validity 365 \
        -keystore $KEY_STORE_P12 \
        -storepass $KEY_STORE_PASS \
        -keypass $KEY_PASS

keytool -certreq \
        -keystore $KEY_STORE_P12 \
        -storepass $KEY_STORE_PASS \
        -keypass $KEY_PASS \
        -alias $LOCAL_CERT_ALIAS \
        -file $KEY_STORE_CSR

keytool -gencert \
        -keystore $SELF_CA_KEY_STORE_P12 \
        -storepass $KEY_STORE_PASS \
        -keypass $KEY_PASS \
        -infile $KEY_STORE_CSR \
        -alias $SELF_CA_CERT_ALIAS \
        -ext BC:c=ca:false \
        -ext EKU:c=serverAuth \
        -ext "SAN:c=DNS:localhost,IP:127.0.0.1" \
        -validity 365 \
        -rfc -outfile $KEY_STORE_PEM

keytool -importcert \
        -noprompt \
        -keystore $KEY_STORE_P12 \
        -storepass $KEY_STORE_PASS \
        -keypass $KEY_PASS \
        -alias $SELF_CA_CERT_ALIAS \
        -file $SELF_CA_KEY_STORE_PEM

keytool -importcert \
        -noprompt \
        -keystore $KEY_STORE_P12 \
        -storepass $KEY_STORE_PASS \
        -keypass $KEY_PASS \
        -alias $LOCAL_CERT_ALIAS \
        -file $KEY_STORE_PEM