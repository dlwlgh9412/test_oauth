package com.copago.test_oauth.app.domain;

import com.copago.test_oauth.auth.domain.common.BaseTimeEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Entity
@Table(name = "tb_app_version")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AppVersion extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Integer versionCode;

    @Column(nullable = false, length = 50)
    private String versionName;

    @Column(nullable = false)
    private Integer minSupportedVersion;

    @Column(nullable = false)
    private Integer latestVersion;

    private Boolean forceUpdate;

    @Column(length = 500)
    private String updateMessage;

    @Column(nullable = false, length = 20)
    private String platform;
}
