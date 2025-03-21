package com.copago.test_oauth.auth.domain.user;

public enum AuthProvider {
    LOCAL,
    KAKAO,
    NAVER;

    public static AuthProvider fromName(String providerId) {
        for (AuthProvider authProvider : AuthProvider.values()) {
            if (authProvider.name().equalsIgnoreCase(providerId)) {
                return authProvider;
            }
        }
        throw new IllegalArgumentException("Unknown provider: " + providerId);
    }
}
