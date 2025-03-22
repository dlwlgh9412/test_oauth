package com.copago.test_oauth.auth.service;

import com.copago.test_oauth.auth.dto.AuthResponse;
import com.copago.test_oauth.auth.dto.LoginRequest;
import com.copago.test_oauth.auth.security.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final LoginAttemptService loginAttemptService;

    /**
     * Authenticates a user with username and password
     */
    public AuthResponse login(LoginRequest loginRequest, HttpServletRequest request) {
        String email = loginRequest.getEmail();
        String clientIp = getClientIp(request);

        // Check if user is blocked due to too many failed attempts
        if (loginAttemptService.isBlocked(email, clientIp)) {
            log.warn("Account locked for email: {} from IP: {}", email, clientIp);
            throw new BadCredentialsException("Account temporarily locked. Too many failed attempts.");
        }

        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            email,
                            loginRequest.getPassword()
                    )
            );

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Reset failed attempts on successful login
            loginAttemptService.loginSucceeded(email, clientIp);

            // Generate tokens
            return tokenService.createTokenPair(authentication, request);
        } catch (AuthenticationException e) {
            // Record failed login attempt
            loginAttemptService.loginFailed(email, clientIp);
            log.warn("Failed login attempt for email: {} from IP: {}", email, clientIp);
            throw new BadCredentialsException("Invalid email or password");
        }
    }

    /**
     * Refresh access token using a valid refresh token
     */
    public AuthResponse refreshToken(String refreshToken, HttpServletRequest request) {
        return tokenService.refreshToken(refreshToken, request);
    }

    /**
     * Logout a user by invalidating their refresh token
     */
    public void logout(String refreshToken) {
        tokenService.logout(refreshToken);
        SecurityContextHolder.clearContext();
    }

    /**
     * Gets the client IP address, handling proxy servers
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
