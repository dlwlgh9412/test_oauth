package com.copago.test_oauth.app.repository;

import com.copago.test_oauth.app.domain.VersionFeature;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface VersionFeatureRepository extends JpaRepository<VersionFeature, Long> {
    List<VersionFeature> findByPlatformAndVersionCodeGreaterThanEqual(String platform, Integer versionCode);

    Optional<VersionFeature> findByPlatformAndFeatureName(String platform, String featureName);

    @Query("SELECT vf FROM VersionFeature vf WHERE vf.platform = :platform AND vf.featureName = :featureName AND vf.versionCode <= :versionCode ORDER BY vf.versionCode DESC LIMIT 1")
    Optional<VersionFeature> findLatestFeatureForVersion(String platform, String featureName, Integer versionCode);

}
