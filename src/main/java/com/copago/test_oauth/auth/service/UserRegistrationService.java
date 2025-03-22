package com.copago.test_oauth.auth.service;

import com.copago.test_oauth.auth.domain.user.AuthProvider;
import com.copago.test_oauth.auth.domain.user.Role;
import com.copago.test_oauth.auth.domain.user.User;
import com.copago.test_oauth.auth.dto.SignUpRequest;
import com.copago.test_oauth.auth.exception.BadRequestException;
import com.copago.test_oauth.auth.repository.RoleRepository;
import com.copago.test_oauth.auth.repository.UserRepository;
import com.copago.test_oauth.auth.security.PasswordValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserRegistrationService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordValidator passwordValidator;

    /**
     * Registers a new user in the system
     */
    @Transactional
    public User registerUser(SignUpRequest signUpRequest) {
        // Validate that email is not already in use
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            log.warn("Email address already in use: {}", signUpRequest.getEmail());
            throw new BadRequestException("Email address already in use");
        }

        // Validate password strength
        if (!passwordValidator.isValid(signUpRequest.getPassword())) {
            log.warn("Password does not meet strength requirements for email: {}", signUpRequest.getEmail());
            throw new BadRequestException(
                    "Password must be at least 8 characters long and contain at least one uppercase letter, " +
                            "one lowercase letter, one digit, and one special character");
        }

        // Create new user
        User user = User.builder()
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .provider(AuthProvider.LOCAL)
                .emailVerified(false)
                .build();

        // Assign default role
        Role userRole = roleRepository.findByName(Role.RoleName.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Default user role not found"));
        user.addRole(userRole);

        // Save user
        User savedUser = userRepository.save(user);
        log.info("Registered new user: {}, id: {}", savedUser.getEmail(), savedUser.getId());

        return savedUser;
    }
}
