package com.civicconnect.auth_service.controller;

import com.civicconnect.auth_service.config.JwtTokenProvider;
import com.civicconnect.auth_service.dto.AuthResponseDto;
import com.civicconnect.auth_service.model.User;
import com.civicconnect.auth_service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Optional;

@Controller
@RequestMapping("/api/auth")
public class AuthController {

    private UserService userService;
    private PasswordEncoder passwordEncoder;
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    public AuthController(UserService userService, BCryptPasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider, JwtTokenProvider jwtTokenProvider1) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider1;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDto> registerUser(@RequestBody User user) {
        Optional<User> existingUser = Optional.ofNullable(userService.findByUsername(user.getUsername()));
        if (existingUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(null);
        }
        User savedUser = userService.saveUser(user);
        String token = jwtTokenProvider.generateToken(user.getUsername(), user.getRole());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getUsername());

        return ResponseEntity.status(HttpStatus.CREATED).body(new AuthResponseDto(token, refreshToken));

    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthResponseDto> authenticateUser(@RequestBody User loginUser) {
        Optional<User> existingUser = Optional.ofNullable(userService.findByUsername(loginUser.getUsername()));
        if (existingUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        boolean passwordMatch = passwordEncoder.matches(loginUser.getPassword(), existingUser.get().getPassword());
        if (!passwordMatch) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        String token = jwtTokenProvider.generateToken(existingUser.get().getUsername(), existingUser.get().getRole());
        String refreshToken = jwtTokenProvider.generateRefreshToken(existingUser.get().getUsername());

        return ResponseEntity.ok(new AuthResponseDto(token, refreshToken));
    }
}
