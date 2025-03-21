package com.copago.test_oauth;

import com.copago.test_oauth.auth.domain.user.Role;
import com.copago.test_oauth.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableScheduling;

@Slf4j
@SpringBootApplication
@EnableJpaAuditing
@EnableCaching
@EnableScheduling
@EnableConfigurationProperties
@RequiredArgsConstructor
public class TestOauthApplication {

    public static void main(String[] args) {
        SpringApplication.run(TestOauthApplication.class, args);
    }

    /**
     * 기본 역할 초기화 - 애플리케이션 시작 시 실행
     */
    @Bean
    public CommandLineRunner initRoles(RoleRepository roleRepository) {
        return args -> {
            log.info("Initializing roles...");

            // 사용자 역할이 없으면 생성
            if (!roleRepository.findByName(Role.RoleName.ROLE_USER).isPresent()) {
                Role userRole = Role.builder()
                        .name(Role.RoleName.ROLE_USER)
                        .build();
                roleRepository.save(userRole);
                log.info("ROLE_USER created");
            }

            // 관리자 역할이 없으면 생성
            if (!roleRepository.findByName(Role.RoleName.ROLE_ADMIN).isPresent()) {
                Role adminRole = Role.builder()
                        .name(Role.RoleName.ROLE_ADMIN)
                        .build();
                roleRepository.save(adminRole);
                log.info("ROLE_ADMIN created");
            }
        };
    }
}
