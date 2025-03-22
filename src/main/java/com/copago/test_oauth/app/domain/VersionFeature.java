package com.copago.test_oauth.app.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "tb_version_feature")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VersionFeature {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Integer versionCode;

    @Column(nullable = false, length = 100)
    private String featureName;

    @Column(length = 500)
    private String featureDescription;

    private Boolean enabled;

    @Column(nullable = false, length = 20)
    private String platform;
}
