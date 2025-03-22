package com.copago.test_oauth.auth.controller;

import com.copago.test_oauth.auth.config.SecureCookieConfig;
import com.copago.test_oauth.auth.domain.user.User;
import com.copago.test_oauth.auth.dto.*;
import com.copago.test_oauth.auth.service.AuthenticationService;
import com.copago.test_oauth.auth.service.UserRegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
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
    private final AuthenticationService authenticationService;
    private final UserRegistrationService userRegistrationService;
    private final SecureCookieConfig secureCookieConfig;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        AuthResponse authResponse = authenticationService.login(loginRequest, request);

        if (authResponse != null && authResponse.getAccessToken() != null) {
            AuthResponse sanitizedResponse = secureCookieConfig.addTokenCookies(response, authResponse);
            return ResponseEntity.ok(sanitizedResponse);
        }

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody SignUpRequest signUpRequest) {
        User user = userRegistrationService.registerUser(signUpRequest);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/v1/users/{id}")
                .buildAndExpand(user.getId()).toUri();

        UserResponse userResponse = UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .provider(user.getProvider())
                .build();

        return ResponseEntity.created(location).body(userResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody(required = false) TokenRefreshRequest requestBody, HttpServletRequest request, HttpServletResponse response) {

        // Try to get refresh token from cookie first, then from request body
        String refreshToken = secureCookieConfig.getRefreshTokenFromCookies(request);

        // If not in cookie, try to get from request body
        if (refreshToken == null && requestBody != null) {
            refreshToken = requestBody.getRefreshToken();
        }

        // If still null, return error
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(null);
        }

        // Refresh the token
        AuthResponse authResponse = authenticationService.refreshToken(refreshToken, request);

        // For cookie-based token storage
        if (authResponse != null && authResponse.getAccessToken() != null) {
            // Add secure cookies and strip tokens from response body
            AuthResponse sanitizedResponse = secureCookieConfig.addTokenCookies(response, authResponse);
            return ResponseEntity.ok(sanitizedResponse);
        }

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(@RequestBody(required = false) TokenRefreshRequest requestBody, HttpServletRequest request, HttpServletResponse response) {

        // Try to get refresh token from cookie first, then from request body
        String refreshToken = secureCookieConfig.getRefreshTokenFromCookies(request);

        // If not in cookie, try to get from request body
        if (refreshToken == null && requestBody != null) {
            refreshToken = requestBody.getRefreshToken();
        }

        // Log the user out if we have a refresh token
        if (refreshToken != null) {
            authenticationService.logout(refreshToken);
        }

        // Clear cookies regardless
        secureCookieConfig.clearTokenCookies(request, response);

        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }
}
