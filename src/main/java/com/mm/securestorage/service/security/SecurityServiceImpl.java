package com.mm.securestorage.service.security;

import com.mm.securestorage.model.User;
import com.mm.securestorage.service.security.crypto.AesCrypto;
import com.mm.securestorage.service.security.crypto.AwsKmsCrypto;
import com.mm.securestorage.service.security.crypto.EnvelopeCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
public class SecurityServiceImpl implements SecurityService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Qualifier("userDetailsServiceImpl")
    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(SecurityServiceImpl.class);

    @Override
    public boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder
            .getContext()
            .getAuthentication();

        if (
            authentication == null || AnonymousAuthenticationToken.class
                .isAssignableFrom(authentication.getClass())
        ) {
            return false;
        }

        return authentication.isAuthenticated();
    }

    @Override
    public String getAuthenticatedUsername() {
        return SecurityContextHolder
            .getContext()
            .getAuthentication()
            .getName();
    }

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public void hashUserPassword(User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    }

    @Override
    public void autoLogin(String username, String password) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            password,
            userDetails.getAuthorities()
        );

        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        if (usernamePasswordAuthenticationToken.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            logger.debug(String.format("Auto login %s successfully!", username));
        }
    }

    @Value("${aws.kms.arn}")
    private String AWS_KMS_ARN;

    @Override
    public String getUserSensitiveData(User user) {
        String encryptedData = user.getSensitiveData();

        if (encryptedData != null) {
            byte[] encodedData = Base64.getDecoder().decode(encryptedData);

            EnvelopeCrypto crypto = new EnvelopeCrypto(
                new AesCrypto(),
                new AwsKmsCrypto(AWS_KMS_ARN)
            );

            byte[] decryptedData = crypto.decrypt(encodedData);
            return new String(decryptedData);
        }

        return null;
    }

    @Override
    public void setUserSensitiveData(User user, String data) {
        if (data != null) {
            EnvelopeCrypto crypto = new EnvelopeCrypto(
                new AesCrypto(),
                new AwsKmsCrypto(AWS_KMS_ARN)
            );

            byte[] encryptedData = crypto.encrypt(data.getBytes());
            String encodedData = Base64.getEncoder().encodeToString(encryptedData);

            user.setSensitiveData(encodedData);
        }
    }

}
