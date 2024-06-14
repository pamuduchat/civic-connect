package com.civicconnect.auth_service.service;

import com.civicconnect.auth_service.model.User;
import org.springframework.stereotype.Service;

public interface UserService {
    User saveUser(User user);

    User findByUsername(String username);

}
