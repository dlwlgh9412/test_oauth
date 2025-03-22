package com.copago.test_oauth.app.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VersionCheckResponse {
    private boolean updateRequired;
    private boolean forceUpdate;
    private String latestVersion;
    private String updateMessage;
    private String status;
    private Map<String, Boolean> features;
}
