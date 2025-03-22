package com.copago.test_oauth.app.service;

import com.copago.test_oauth.app.domain.AppVersion;
import com.copago.test_oauth.app.domain.VersionCheckLog;
import com.copago.test_oauth.app.domain.VersionFeature;
import com.copago.test_oauth.app.dto.VersionCheckRequest;
import com.copago.test_oauth.app.dto.VersionCheckResponse;
import com.copago.test_oauth.app.exception.NotSupportPlatform;
import com.copago.test_oauth.app.repository.AppVersionRepository;
import com.copago.test_oauth.app.repository.VersionCheckLogRepository;
import com.copago.test_oauth.app.repository.VersionFeatureRepository;
import com.copago.test_oauth.util.NetworkUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AppVersionService {
    private final AppVersionRepository appVersionRepository;
    private final VersionFeatureRepository versionFeatureRepository;
    private final VersionCheckLogRepository versionCheckLogRepository;

    @Transactional
    public VersionCheckResponse checkVersion(VersionCheckRequest request, HttpServletRequest servletRequest) {
        String ipAddress = NetworkUtils.getClientIpAddress(servletRequest);

        // 현재 플랫폼의 버전 정보 조회
        AppVersion currentVersion = appVersionRepository.findByPlatform(request.getPlatform())
                .orElseThrow(() -> new NotSupportPlatform("Unsupported platform: " + request.getPlatform()));

        // 버전 체크 결과 상태 확인
        String status = determineStatus(request.getAppVersion(), currentVersion);

        Map<String, Boolean> features = getAvailableFeatures(request.getPlatform(), request.getAppVersion());

        saveVersionCheckLog(request, status, ipAddress);

        return VersionCheckResponse.builder()
                .updateRequired(isUpdateRequired(status))
                .forceUpdate(isForceUpdateRequired(status, currentVersion))
                .latestVersion(currentVersion.getVersionName())
                .updateMessage(currentVersion.getUpdateMessage())
                .status(status)
                .features(features)
                .build();
    }

    @Transactional
    public AppVersion updateAppVersion(AppVersion appVersion) {
        return appVersionRepository.save(appVersion);
    }

    @Transactional
    public VersionFeature updateFeature(VersionFeature feature) {
        return versionFeatureRepository.save(feature);
    }

    public boolean isFeatureEnabled(String platform, String featureName, Integer versionCode) {
        return versionFeatureRepository.findLatestFeatureForVersion(platform, featureName, versionCode)
                .map(VersionFeature::getEnabled)
                .orElse(false);
    }

    private String determineStatus(Integer appVersion, AppVersion currentVersion) {
        if (appVersion < currentVersion.getMinSupportedVersion()) {
            return "UPDATE_REQUIRED";
        } else if (appVersion < currentVersion.getLatestVersion()) {
            return "UPDATE_AVAILABLE";
        }
        return "UP_TO_DATE";
    }

    private boolean isUpdateRequired(String status) {
        return "UPDATE_REQUIRED".equals(status);
    }

    private boolean isForceUpdateRequired(String status, AppVersion currentVersion) {
        return "UPDATE_REQUIRED".equals(status) && currentVersion.getForceUpdate();
    }

    private Map<String, Boolean> getAvailableFeatures(String platform, Integer versionCode) {
        List<VersionFeature> features = versionFeatureRepository
                .findByPlatformAndVersionCodeGreaterThanEqual(platform, versionCode);

        Map<String, Boolean> featureMap = new HashMap<>();
        features.forEach(feature -> featureMap.put(feature.getFeatureName(), feature.getEnabled()));

        return featureMap;
    }

    private void saveVersionCheckLog(VersionCheckRequest request, String status, String ipAddress) {
        VersionCheckLog log = VersionCheckLog.builder()
                .deviceId(request.getDeviceId())
                .appVersion(request.getAppVersion())
                .platform(request.getPlatform())
                .osVersion(request.getOsVersion())
                .deviceModel(request.getDeviceModel())
                .checkResult(status)
                .ipAddress(ipAddress)
                .build();

        versionCheckLogRepository.save(log);
    }
}
