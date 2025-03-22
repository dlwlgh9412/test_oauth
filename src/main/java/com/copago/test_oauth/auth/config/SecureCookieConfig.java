package com.copago.test_oauth.auth.config;

import com.copago.test_oauth.auth.dto.AuthResponse;
import com.copago.test_oauth.auth.util.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class SecureCookieConfig {
    private final AppProperties appProperties;
    private final EnvironmentService environmentService;

    // Constants for cookie settings
    private static final String ACCESS_TOKEN_COOKIE_PATH = "/api";
    private static final String REFRESH_TOKEN_COOKIE_PATH = "/api/v1/auth";
    private static final String SAME_SITE_STRICT = "Strict";
    private static final String SAME_SITE_LAX = "Lax";

    /**
     * Adds secure cookies for JWT tokens
     *
     * @param response HTTP response
     * @param authResponse Auth response containing tokens
     * @return Auth response with client-visible fields only
     */
    public AuthResponse addTokenCookies(HttpServletResponse response, AuthResponse authResponse) {
        boolean isProduction = environmentService.isProduction();

        // Access token cookie - shorter-lived, more restrictive
        CookieUtils.addCookie(
                response,
                appProperties.getAuth().getTokenCookieName(),
                authResponse.getAccessToken(),
                authResponse.getExpiresIn(),
                true,                               // httpOnly
                isProduction,                       // secure flag (true in production)
                isProduction ? SAME_SITE_STRICT : SAME_SITE_LAX,    // SameSite (Strict in production)
                ACCESS_TOKEN_COOKIE_PATH            // path
        );

        // Refresh token cookie - longer-lived, more restrictive path
        CookieUtils.addCookie(
                response,
                appProperties.getAuth().getRefreshTokenCookieName(),
                authResponse.getRefreshToken(),
                (int) TimeUnit.MILLISECONDS.toSeconds(appProperties.getAuth().getRefreshTokenExpiration()),
                true,                               // httpOnly
                isProduction,                       // secure flag (true in production)
                isProduction ? SAME_SITE_STRICT : SAME_SITE_LAX,    // SameSite (Strict in production)
                REFRESH_TOKEN_COOKIE_PATH           // path - more restrictive for refresh token
        );

        // Return a modified auth response without the sensitive tokens
        // This prevents tokens from being exposed in the response body
        return AuthResponse.builder()
                .tokenType(authResponse.getTokenType())
                .expiresIn(authResponse.getExpiresIn())
                .build();
    }

    /**
     * Clears token cookies
     */
    public void clearTokenCookies(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, appProperties.getAuth().getTokenCookieName());
        CookieUtils.deleteCookie(request, response, appProperties.getAuth().getRefreshTokenCookieName());
    }

    /**
     * Extracts refresh token from cookie
     */
    public String getRefreshTokenFromCookies(HttpServletRequest request) {
        return CookieUtils.getCookie(request, appProperties.getAuth().getRefreshTokenCookieName())
                .map(cookie -> cookie.getValue())
                .orElse(null);
    }
}
