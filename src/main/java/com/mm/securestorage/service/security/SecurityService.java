package com.mm.securestorage.service.security;

public interface SecurityService {

    boolean isAuthenticated();

    String findLoggedInUsername();

    void autoLogin(String username, String password);

}
