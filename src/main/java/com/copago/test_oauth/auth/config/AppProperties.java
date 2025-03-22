package com.copago.test_oauth.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    private final Auth auth = new Auth();
    private final Cors cors = new Cors();

    @Getter
    @Setter
    public static class Auth {
        // JWT 토큰 설정
        private String tokenSecret;
        private long accessTokenExpiration;
        private long refreshTokenExpiration;

        // 토큰 쿠키 사용 여부 및 설정
        private boolean useTokenCookie = false;
        private String tokenCookieName = "access_token";
        private String refreshTokenCookieName = "refresh_token";

        // 리다이렉트 URI 검증 설정
        private List<String> allowedRedirectOrigins = new ArrayList<>();
        private boolean requireHttps = true;

        // 기본 리다이렉트 URL (fallback)
        private String defaultRedirectUrl = "http://localhost:3000";
    }

    @Getter
    @Setter
    public static class Cors {
        private String allowedOrigins;
        private long maxAge;
    }
}
