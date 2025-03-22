package com.copago.test_oauth.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class EnvironmentService {
    private final Environment environment;

    @Autowired
    public EnvironmentService(Environment environment) {
        this.environment = environment;
    }

    /**
     * Checks if the application is running in production
     */
    public boolean isProduction() {
        String[] activeProfiles = environment.getActiveProfiles();
        return Arrays.asList(activeProfiles).contains("prod");
    }

    /**
     * Checks if the application is running in development
     */
    public boolean isDevelopment() {
        String[] activeProfiles = environment.getActiveProfiles();
        return Arrays.asList(activeProfiles).contains("dev");
    }
}
