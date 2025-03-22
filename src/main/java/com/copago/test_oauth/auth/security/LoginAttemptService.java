package com.copago.test_oauth.auth.security;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class LoginAttemptService {
    private static final int MAX_ATTEMPT = 5;
    private static final int BLOCK_DURATION_MINUTES = 15;

    private final LoadingCache<String, Integer> attemptsCache;

    public LoginAttemptService() {
        attemptsCache = CacheBuilder.newBuilder()
                .expireAfterWrite(BLOCK_DURATION_MINUTES, TimeUnit.MINUTES)
                .build(new CacheLoader<>() {
                    @Override
                    public Integer load(String key) {
                        return 0;
                    }
                });
    }

    /**
     * Records a failed login attempt
     *
     * @param username The username that failed to login
     * @param ip The IP address from which the login attempt was made
     */
    public void loginFailed(String username, String ip) {
        String key = getCacheKey(username, ip);
        int attempts;

        try {
            attempts = attemptsCache.get(key);
        } catch (ExecutionException e) {
            attempts = 0;
        }

        attempts++;
        attemptsCache.put(key, attempts);

        log.debug("Login failed for user: {}, IP: {}, attempts: {}", username, ip, attempts);
    }

    /**
     * Resets the failed login attempts counter on successful login
     *
     * @param username The username that successfully logged in
     * @param ip The IP address from which the login was made
     */
    public void loginSucceeded(String username, String ip) {
        String key = getCacheKey(username, ip);
        attemptsCache.invalidate(key);
        log.debug("Login succeeded for user: {}, IP: {}, attempts reset", username, ip);
    }

    /**
     * Checks if a user is blocked due to too many failed login attempts
     *
     * @param username The username to check
     * @param ip The IP address to check
     * @return true if the user should be blocked, false otherwise
     */
    public boolean isBlocked(String username, String ip) {
        String key = getCacheKey(username, ip);
        try {
            return attemptsCache.get(key) >= MAX_ATTEMPT;
        } catch (ExecutionException e) {
            return false;
        }
    }

    /**
     * Creates a cache key combining username and IP
     * This allows blocking based on both user account and IP address
     */
    private String getCacheKey(String username, String ip) {
        return username + "_" + ip;
    }
}
