package com.civicconnect.auth_service.controller;

import com.civicconnect.auth_service.model.User;
import com.civicconnect.auth_service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Optional;

@Controller
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        // Check if username is already taken
        Optional<User> existingUser = Optional.ofNullable(userService.findByUsername(user.getUsername()));
        if (existingUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
        userService.saveUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticateUser(@RequestBody User loginUser) {
        // Find user by username
        Optional<User> existingUser = Optional.ofNullable(userService.findByUsername(loginUser.getUsername()));
        if (existingUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // Verify password
        boolean passwordMatch = bCryptPasswordEncoder.matches(loginUser.getPassword(), existingUser.get().getPassword());
        if (!passwordMatch) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        return ResponseEntity.ok("User authenticated successfully");
    }
}
