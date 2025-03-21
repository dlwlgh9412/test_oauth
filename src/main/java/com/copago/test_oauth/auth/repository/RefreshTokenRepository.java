package com.copago.test_oauth.auth.repository;

import com.copago.test_oauth.auth.domain.token.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("delete from RefreshToken t where t.expiryDate <= ?1")
    void deleteAllExpiredTokens(Instant now);

    @Modifying
    @Query("update RefreshToken t set t.revoked = true where t.userId = ?1 and t.revoked = false")
    void revokeAllUserTokens(Long userId);

    List<RefreshToken> findAllByUserId(Long userId);
}
