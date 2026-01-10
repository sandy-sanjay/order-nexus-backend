package com.ordernexus.order_nexus_backend.auth;

import com.ordernexus.order_nexus_backend.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    // ✅ manual constructor (fixes not initialized error)
    public AuthController(JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        if (!request.getUsername().equals("admin") ||
                !request.getPassword().equals("admin123")) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

        String token = jwtUtil.generateToken("admin");

        return ResponseEntity.ok(new LoginResponse(token, "admin", "ADMIN"));
    }
}
