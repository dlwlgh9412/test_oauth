package com.copago.test_oauth.auth.controller;

import com.copago.test_oauth.auth.domain.user.User;
import com.copago.test_oauth.auth.dto.*;
import com.copago.test_oauth.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest,
                                              HttpServletRequest request) {
        return ResponseEntity.ok(authService.login(loginRequest, request));
    }

    @PostMapping("/signup")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody SignUpRequest signUpRequest) {
        User user = authService.register(signUpRequest);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/v1/users/{id}")
                .buildAndExpand(user.getId()).toUri();

        return ResponseEntity.created(location)
                .body(UserResponse.builder()
                        .id(user.getId())
                        .name(user.getName())
                        .email(user.getEmail())
                        .provider(user.getProvider())
                        .build());
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody TokenRefreshRequest request,
                                                     HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.refreshToken(request, httpRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(@Valid @RequestBody TokenRefreshRequest request) {
        authService.logout(request.getRefreshToken());
        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }
}
