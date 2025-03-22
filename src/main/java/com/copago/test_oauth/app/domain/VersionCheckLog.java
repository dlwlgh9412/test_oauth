package com.copago.test_oauth.app.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "tb_version_check_log")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VersionCheckLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 100)
    private String deviceId;

    @Column(nullable = false)
    private Integer appVersion;

    @Column(nullable = false, length = 20)
    private String platform;

    @Column(length = 50)
    private String osVersion;

    @Column(length = 100)
    private String deviceModel;

    @Column(nullable = false, length = 20)
    private String checkResult;

    @Column(length = 50)
    private String ipAddress;
}
