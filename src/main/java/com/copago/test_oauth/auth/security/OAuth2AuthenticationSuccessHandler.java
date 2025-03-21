package com.copago.test_oauth.auth.security;

import com.copago.test_oauth.auth.config.AppProperties;
import com.copago.test_oauth.auth.domain.token.RefreshToken;
import com.copago.test_oauth.auth.repository.RefreshTokenRepository;
import com.copago.test_oauth.auth.util.CookieUtils;
import com.copago.test_oauth.auth.util.RedirectUriValidator;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenProvider tokenProvider;
    private final AppProperties appProperties;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RedirectUriValidator redirectUriValidator;

    // 쿠키 관련 상수 정의
    private static final String REDIRECT_URI_COOKIE_NAME = "redirect_uri";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        log.debug("Redirecting to: {}", targetUrl);
        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to target url {}", targetUrl);
            return;
        }

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // 쿠키에서 리다이렉트 URI 얻기
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_COOKIE_NAME)
                .map(Cookie::getValue);

        // 리다이렉트 URI가 없거나 유효하지 않으면 기본 URL 사용
        if (redirectUri.isPresent() && !redirectUriValidator.isValidRedirectUri(redirectUri.get())) {
            log.warn("Invalid redirect URI detected: {}", redirectUri.get());
            throw new IllegalArgumentException("Invalid redirect URI");
        }

        String defaultUrl = appProperties.getAuth().getDefaultRedirectUrl();
        String targetUrl = redirectUri.orElse(defaultUrl);

        // 사용자 인증 정보 및 토큰 생성
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        String token = tokenProvider.createToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(userPrincipal.getId());

        // 리프레시 토큰 저장
        saveRefreshToken(userPrincipal.getId(), refreshToken, request);

        // 토큰 전달 방식 결정 (쿼리 파라미터 또는 쿠키)
        if (appProperties.getAuth().isUseTokenCookie()) {
            // 쿠키에 토큰 저장
            addTokenCookies(response, token, refreshToken);
            return targetUrl;
        } else {
            // 쿼리 파라미터로 토큰 전달
            return UriComponentsBuilder.fromUriString(targetUrl)
                    .queryParam("token", token)
                    .queryParam("refresh_token", refreshToken)
                    .build().toUriString();
        }
    }

    private void addTokenCookies(HttpServletResponse response, String token, String refreshToken) {
        // 액세스 토큰 쿠키 설정
        CookieUtils.addCookie(response,
                appProperties.getAuth().getTokenCookieName(),
                token,
                (int) TimeUnit.MILLISECONDS.toSeconds(appProperties.getAuth().getTokenExpirationMsec()),
                true,       // httpOnly
                false,       // secure (HTTPS 환경에서만)
                "Strict",   // SameSite policy
                "/");       // path

        // 리프레시 토큰 쿠키 설정
        CookieUtils.addCookie(response,
                appProperties.getAuth().getRefreshTokenCookieName(),
                refreshToken,
                (int) TimeUnit.MILLISECONDS.toSeconds(appProperties.getAuth().getRefreshTokenExpirationMsec()),
                true,
                false,
                "Strict",
                "/");
    }

    private void saveRefreshToken(Long userId, String token, HttpServletRequest request) {
        String ipAddress = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(token)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiryDate(Instant.now().plusMillis(appProperties.getAuth().getRefreshTokenExpirationMsec()))
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    // IP 주소를 추출하는 개선된 메서드 (프록시/로드밸런서 고려)
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // X-Forwarded-For 헤더가 있으면 첫 번째 IP 사용
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
