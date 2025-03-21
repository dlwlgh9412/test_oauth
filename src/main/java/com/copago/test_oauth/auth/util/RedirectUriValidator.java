package com.copago.test_oauth.auth.util;

import com.copago.test_oauth.auth.config.AppProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class RedirectUriValidator {
    private final AppProperties appProperties;

    /**
     * 리다이렉트 URI가 허용된 URI 목록에 포함되어 있는지 검증합니다.
     *
     * @param uri 검증할 리다이렉트 URI
     * @return 유효한 URI인 경우 true, 아니면 false
     */
    public boolean isValidRedirectUri(String uri) {
        if (uri == null || uri.isEmpty()) {
            return false;
        }

        // URI 구문 확인
        URI redirectUri;
        try {
            redirectUri = new URI(uri);
        } catch (URISyntaxException e) {
            return false;
        }

        // HTTPS 강제 (옵션에 따라)
        if (appProperties.getAuth().isRequireHttps() && !"https".equals(redirectUri.getScheme())) {
            return false;
        }

        // 허용된 오리진 목록에서 확인
        List<String> allowedOrigins = appProperties.getAuth().getAllowedRedirectOrigins();

        // 오리진 형식으로 변환 (scheme://host:port)
        String redirectOrigin = redirectUri.getScheme() + "://" + redirectUri.getHost() +
                (redirectUri.getPort() != -1 ? ":" + redirectUri.getPort() : "");

        return allowedOrigins.contains(redirectOrigin) || allowedOrigins.contains("*");
    }
}
