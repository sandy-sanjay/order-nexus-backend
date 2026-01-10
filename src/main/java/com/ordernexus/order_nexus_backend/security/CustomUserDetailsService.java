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
    public UserDetails loadUserByUsername(String username) {

        // TEMP: hardcoded admin
        if (username.equals("admin")) {
            return User.builder()
                    .username("admin")
                    .password("admin123")
                    .roles("ADMIN")
                    .build();
        }

        throw new UsernameNotFoundException("User not found");
    }
}
