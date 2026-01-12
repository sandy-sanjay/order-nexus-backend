package com.ordernexus.order_nexus_backend.auth;


import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private AuthRepository repository;

    @Autowired
    private PasswordEncoder encoder;

    public AuthUser save(AuthUser user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return repository.save(user);
    }

    public Optional<AuthUser> findByUsername(String username) {
        return repository.findByUsername(username);
    }
}
