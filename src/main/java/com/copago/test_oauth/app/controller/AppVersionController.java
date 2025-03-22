package com.copago.test_oauth.app.controller;

import com.copago.test_oauth.app.domain.AppVersion;
import com.copago.test_oauth.app.domain.VersionFeature;
import com.copago.test_oauth.app.dto.VersionCheckRequest;
import com.copago.test_oauth.app.dto.VersionCheckResponse;
import com.copago.test_oauth.app.service.AppVersionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/version")
@RequiredArgsConstructor
public class AppVersionController {
    private final AppVersionService appVersionService;

    @PostMapping("/check")
    public ResponseEntity<VersionCheckResponse> checkVersion(@Valid @RequestBody VersionCheckRequest request, HttpServletRequest servletRequest) {
        VersionCheckResponse response = appVersionService.checkVersion(request, servletRequest);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/feature")
    public ResponseEntity<Boolean> checkFeature(@RequestParam("platform") String platform, @RequestParam("feature") String featureName, @RequestParam("version") Integer versionCode) {
        boolean isEnabled = appVersionService.isFeatureEnabled(platform, featureName, versionCode);
        return ResponseEntity.ok(isEnabled);
    }

    @PostMapping("/admin/app-version")
    public ResponseEntity<AppVersion> updateAppVersion(@Valid @RequestBody AppVersion appVersion) {
        AppVersion updated = appVersionService.updateAppVersion(appVersion);
        return ResponseEntity.ok(updated);
    }

    @PostMapping("/admin/feature")
    public ResponseEntity<VersionFeature> updateFeature(@Valid @RequestBody VersionFeature feature) {
        VersionFeature updated = appVersionService.updateFeature(feature);
        return ResponseEntity.ok(updated);
    }
}
