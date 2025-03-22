package com.copago.test_oauth.app.repository;

import com.copago.test_oauth.app.domain.VersionCheckLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VersionCheckLogRepository extends JpaRepository<VersionCheckLog, Long> {

}
