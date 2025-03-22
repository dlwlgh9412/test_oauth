package com.copago.test_oauth.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class NetworkUtils {

    public static String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // X-Forwarded-For 헤더가 있으면 첫 번째 IP 사용
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
