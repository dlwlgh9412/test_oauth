package com.copago.test_oauth.auth.security;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class PasswordValidator {
    // Minimum 8 characters, at least one uppercase letter, one lowercase letter, one number and one special character
    private static final String PASSWORD_PATTERN =
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";

    private final Pattern pattern;

    public PasswordValidator() {
        pattern = Pattern.compile(PASSWORD_PATTERN);
    }

    /**
     * Validates if a password meets the strength requirements
     *
     * @param password The password to validate
     * @return true if the password is valid, false otherwise
     */
    public boolean isValid(String password) {
        if (password == null) {
            return false;
        }

        return pattern.matcher(password).matches();
    }
}
