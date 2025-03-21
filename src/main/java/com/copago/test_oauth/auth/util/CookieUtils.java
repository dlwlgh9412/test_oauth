package com.copago.test_oauth.auth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;

import java.util.Base64;
import java.util.Optional;

/**
 * 쿠키 관련 유틸리티 클래스
 * 1. SameSite 속성 지원
 * 2. Secure 플래그 지원
 * 3. 쿠키 속성 세부 제어 기능
 * 4. XSS 및 CSRF 방어를 위한 보안 옵션
 */
public class CookieUtils {
    /**
     * 요청에서 특정 이름의 쿠키를 가져옵니다.
     */
    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }

        return Optional.empty();
    }

    /**
     * 응답에 새 쿠키를 추가합니다. (기본 옵션: HttpOnly=true, Secure=false)
     */
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    /**
     * 응답에 새 쿠키를 추가합니다. 보안 속성을 세부적으로 지정할 수 있습니다.
     */
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge,
                                 boolean httpOnly, boolean secure, String sameSite, String path) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath(path);
        cookie.setHttpOnly(httpOnly);
        cookie.setMaxAge(maxAge);
        cookie.setSecure(secure);

        if (sameSite != null) {
            // 쿠키 클래스가 SameSite를 직접 지원하지 않으므로 헤더를 통해 설정
            String cookieHeader = String.format("%s=%s; Max-Age=%d; Path=%s%s%s%s",
                    name, value, maxAge, path,
                    httpOnly ? "; HttpOnly" : "",
                    secure ? "; Secure" : "",
                    "; SameSite=" + sameSite);

            response.addHeader("Set-Cookie", cookieHeader);
        } else {
            response.addCookie(cookie);
        }
    }

    /**
     * JWT 토큰을 위한 보안 쿠키를 추가합니다.
     * 적절한 보안 설정과 함께 토큰을 쿠키에 저장합니다.
     */
    public static void addSecureTokenCookie(HttpServletResponse response, String name, String token, int maxAge, boolean isProduction) {
        // 프로덕션 환경에서는 Secure 및 SameSite=Strict 설정, 개발 환경에서는 더 관대한 설정
        String sameSite = isProduction ? "Strict" : "Lax";
        boolean secure = isProduction;

        addCookie(response, name, token, maxAge, true, secure, sameSite, "/");
    }

    /**
     * 쿠키를 삭제합니다.
     */
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }

    /**
     * 특정 이름의 토큰 쿠키를 보안적으로 삭제합니다.
     * SameSite 및 Secure 속성을 유지하면서 삭제합니다.
     */
    public static void deleteSecureCookie(HttpServletResponse response, String name, boolean isProduction) {
        String sameSite = isProduction ? "Strict" : "Lax";
        boolean secure = isProduction;

        String cookieHeader = String.format("%s=; Max-Age=0; Path=/%s%s%s",
                name,
                "; HttpOnly",
                secure ? "; Secure" : "",
                "; SameSite=" + sameSite);

        response.addHeader("Set-Cookie", cookieHeader);
    }

    /**
     * 객체를 직렬화하여 Base64 인코딩된 문자열로 변환합니다.
     */
    public static String serialize(Object object) {
        return Base64.getUrlEncoder()
                .encodeToString(SerializationUtils.serialize(object));
    }

    /**
     * Base64 인코딩된 쿠키 값을 역직렬화합니다.
     */
    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        return cls.cast(SerializationUtils.deserialize(
                Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}
