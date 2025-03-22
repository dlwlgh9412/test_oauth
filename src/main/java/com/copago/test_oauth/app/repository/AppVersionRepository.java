package com.copago.test_oauth.app.repository;

import com.copago.test_oauth.app.domain.AppVersion;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppVersionRepository extends JpaRepository<AppVersion, Long> {
    Optional<AppVersion> findByPlatform(String platform);
}
