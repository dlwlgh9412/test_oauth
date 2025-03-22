package com.copago.test_oauth.auth.config;

import com.copago.test_oauth.exception.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    // 기본 설정: 1분당 최대 60회 요청
    private static final int CAPACITY = 60;
    private static final int REFILL_TOKENS = 60;
    private static final long REFILL_PERIOD_MS = TimeUnit.MINUTES.toMillis(1);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String clientIp = getClientIp(request);

        // 클라이언트별 토큰 버킷 생성 (없으면)
        TokenBucket tokenBucket = buckets.computeIfAbsent(clientIp,
                k -> new TokenBucket(CAPACITY, REFILL_TOKENS, REFILL_PERIOD_MS));

        // 요청 처리 가능 여부 확인
        if (!tokenBucket.tryConsume(1)) {
            log.warn("Rate limit exceeded for IP: {}", clientIp);
            sendErrorResponse(response, "Too many requests. Please try again later.", HttpStatus.TOO_MANY_REQUESTS);
            return false;
        }

        return true;
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader != null) {
            return xForwardedForHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private void sendErrorResponse(HttpServletResponse response, String message, HttpStatus status) throws IOException {
        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                message,
                "");

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), errorResponse);
    }

    /**
     * 토큰 버킷 알고리즘을 이용한 속도 제한 구현
     */
    static class TokenBucket {
        private final int capacity;
        private final int refillTokens;
        private final long refillPeriodMs;

        private int tokens;
        private long lastRefillTimestamp;

        public TokenBucket(int capacity, int refillTokens, long refillPeriodMs) {
            this.capacity = capacity;
            this.refillTokens = refillTokens;
            this.refillPeriodMs = refillPeriodMs;
            this.tokens = capacity;
            this.lastRefillTimestamp = System.currentTimeMillis();
        }

        synchronized boolean tryConsume(int tokensToConsume) {
            refill();

            if (tokens < tokensToConsume) {
                return false;
            }

            tokens -= tokensToConsume;
            return true;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long timeSinceLastRefill = now - lastRefillTimestamp;

            if (timeSinceLastRefill < refillPeriodMs) {
                return;
            }

            long periodsElapsed = timeSinceLastRefill / refillPeriodMs;
            int tokensToAdd = (int) (periodsElapsed * refillTokens);

            tokens = Math.min(capacity, tokens + tokensToAdd);
            lastRefillTimestamp += periodsElapsed * refillPeriodMs;
        }
    }
}
