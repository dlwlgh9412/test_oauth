package com.copago.test_oauth.app.dto;

import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VersionCheckRequest {
    private String deviceId;

    @NotNull(message = "App version is not null")
    private Integer appVersion;

    @NotNull(message = "Platform is not null")
    private String platform;

    private String osVersion;

    private String deviceModel;
}
