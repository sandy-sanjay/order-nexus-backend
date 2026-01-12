package com.ordernexus.order_nexus_backend.security;

import com.ordernexus.order_nexus_backend.auth.AuthUser;
import com.ordernexus.order_nexus_backend.auth.AuthRepository;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final AuthRepository authRepository;

    public CustomUserDetailsService(AuthRepository authRepository) {
        this.authRepository = authRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        AuthUser user = authRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())   // ✅ BCrypt password from DB
                .roles(user.getRole())
                .build();
    }
}
