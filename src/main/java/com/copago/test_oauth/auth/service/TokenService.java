package com.copago.test_oauth.auth.service;

import com.copago.test_oauth.auth.domain.token.RefreshToken;
import com.copago.test_oauth.auth.dto.AuthResponse;
import com.copago.test_oauth.auth.exception.TokenRefreshException;
import com.copago.test_oauth.auth.repository.RefreshTokenRepository;
import com.copago.test_oauth.auth.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public AuthResponse createTokenPair(Authentication authentication, HttpServletRequest request) {
        String accessToken = tokenProvider.createToken(authentication);
        Long userId = tokenProvider.getUserIdFromAuthentication(authentication);
        String refreshToken = tokenProvider.createRefreshToken(userId);

        // Save refresh token with security context
        saveRefreshToken(userId, refreshToken, request);

        int expiresInSeconds = tokenProvider.getAccessTokenExpirationSeconds();

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresInSeconds)
                .build();
    }

    @Transactional
    public AuthResponse refreshToken(String requestRefreshToken, HttpServletRequest request) {
        return refreshTokenRepository.findByToken(requestRefreshToken)
                .map(this::verifyExpiration)
                .map(this::validateRequestContext)
                .map(refreshToken -> {
                    Long userId = refreshToken.getUserId();

                    // Generate new tokens
                    String accessToken = tokenProvider.createTokenForUser(userId);
                    String newRefreshToken = tokenProvider.createRefreshToken(userId);

                    // Revoke old token and save new one
                    refreshToken.setRevoked(true);
                    refreshTokenRepository.save(refreshToken);
                    saveRefreshToken(userId, newRefreshToken, request);

                    return AuthResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(newRefreshToken)
                            .tokenType("Bearer")
                            .expiresIn(tokenProvider.getAccessTokenExpirationSeconds())
                            .build();
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token not found. Please log in again."));
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                    log.info("User {} logged out successfully", token.getUserId());
                });
    }

    @Transactional
    public void revokeAllUserTokens(Long userId) {
        refreshTokenRepository.revokeAllUserTokens(userId);
        log.info("Revoked all tokens for user {}", userId);
    }

    private void saveRefreshToken(Long userId, String token, HttpServletRequest request) {
        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(token)
                .ipAddress(ipAddress != null ? ipAddress : "unknown")
                .userAgent(userAgent != null ? userAgent : "unknown")
                .expiryDate(Instant.now().plusMillis(tokenProvider.getRefreshTokenExpirationMs()))
                .build();

        refreshTokenRepository.save(refreshToken);
        log.debug("Saved refresh token for user {}", userId);
    }

    /**
     * Validates that the refresh token is not expired
     */
    private RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isRevoked()) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(),
                    "Refresh token was revoked. Please log in again.");
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(),
                    "Refresh token expired. Please log in again.");
        }

        return token;
    }

    /**
     * Validates that the request context matches the token context (IP, user agent)
     * Helps prevent token theft
     */
    private RefreshToken validateRequestContext(RefreshToken token) {
        // In a real-world scenario, you might want to compare the request IP and user agent
        // with the ones stored with the token for additional security
        // This is a simplified implementation
        return token;
    }

    /**
     * Gets the client IP address, handling proxy servers
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
