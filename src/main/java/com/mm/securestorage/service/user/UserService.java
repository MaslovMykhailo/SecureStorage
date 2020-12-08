package com.mm.securestorage.service.user;

import com.mm.securestorage.model.User;

public interface UserService {

    void save(User user);

    User findByUsername(String username);

}
