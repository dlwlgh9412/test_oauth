package com.copago.test_oauth.auth.config;

import com.copago.test_oauth.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenCleanupScheduler {
    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * 만료된 리프레시 토큰을 정기적으로 삭제
     * 매일 자정에 실행
     */
    @Scheduled(cron = "0 0 0 * * ?")
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired refresh tokens");
        refreshTokenRepository.deleteAllExpiredTokens(Instant.now());
    }
}
