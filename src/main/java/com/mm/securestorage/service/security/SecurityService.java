package com.mm.securestorage.service.security;

import com.mm.securestorage.model.User;

public interface SecurityService {

    boolean isAuthenticated();

    String getAuthenticatedUsername();

    void autoLogin(String username, String password);

    void hashUserPassword(User user);

    String getUserSensitiveData(User user);

    void setUserSensitiveData(User user, String data);

}
