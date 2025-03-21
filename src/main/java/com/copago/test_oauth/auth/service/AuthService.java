package com.copago.test_oauth.auth.service;

import com.copago.test_oauth.auth.domain.token.RefreshToken;
import com.copago.test_oauth.auth.domain.user.AuthProvider;
import com.copago.test_oauth.auth.domain.user.Role;
import com.copago.test_oauth.auth.domain.user.User;
import com.copago.test_oauth.auth.dto.AuthResponse;
import com.copago.test_oauth.auth.dto.LoginRequest;
import com.copago.test_oauth.auth.dto.SignUpRequest;
import com.copago.test_oauth.auth.dto.TokenRefreshRequest;
import com.copago.test_oauth.auth.exception.BadRequestException;
import com.copago.test_oauth.auth.exception.ResourceNotFoundException;
import com.copago.test_oauth.auth.exception.TokenRefreshException;
import com.copago.test_oauth.auth.repository.RefreshTokenRepository;
import com.copago.test_oauth.auth.repository.RoleRepository;
import com.copago.test_oauth.auth.repository.UserRepository;
import com.copago.test_oauth.auth.security.JwtTokenProvider;
import com.copago.test_oauth.auth.security.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public AuthResponse login(LoginRequest loginRequest, HttpServletRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        String accessToken = tokenProvider.createToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(userPrincipal.getId());

        // 리프레시 토큰 저장
        saveRefreshToken(userPrincipal.getId(), refreshToken, request);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(3600) // 1 hour
                .build();
    }

    @Transactional
    public AuthResponse refreshToken(TokenRefreshRequest refreshRequest, HttpServletRequest request) {
        String requestRefreshToken = refreshRequest.getRefreshToken();

        return refreshTokenRepository.findByToken(requestRefreshToken)
                .map(this::verifyExpiration)
                .map(RefreshToken::getUserId)
                .map(userId -> {
                    User user = userRepository.findById(userId)
                            .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

                    UserPrincipal userPrincipal = UserPrincipal.create(user);
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            userPrincipal, null, userPrincipal.getAuthorities());

                    String accessToken = tokenProvider.createToken(authentication);

                    // 새로운 리프레시 토큰 발급 (토큰 재사용 방지)
                    String newRefreshToken = tokenProvider.createRefreshToken(userId);
                    saveRefreshToken(userId, newRefreshToken, request);

                    // 이전 리프레시 토큰 무효화
                    revokeRefreshToken(requestRefreshToken);

                    return AuthResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(newRefreshToken)
                            .tokenType("Bearer")
                            .expiresIn(3600) // 1 hour
                            .build();
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token is not found"));
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
    }

    @Transactional
    public User register(SignUpRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new BadRequestException("Email address already in use.");
        }

        User user = User.builder()
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .provider(AuthProvider.LOCAL)
                .emailVerified(false)
                .build();

        // 기본 역할 부여 (USER)
        Role userRole = roleRepository.findByName(Role.RoleName.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Default role not found"));
        user.addRole(userRole);

        return userRepository.save(user);
    }

    @Cacheable(value = "users", key = "#userId")
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
    }

    @CacheEvict(value = "users", key = "#userId")
    public void updateUser(Long userId, User updatedUser) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        user.setName(updatedUser.getName());
        if (updatedUser.getImageUrl() != null) {
            user.setImageUrl(updatedUser.getImageUrl());
        }

        userRepository.save(user);
    }

    @Transactional
    public void revokeAllUserTokens(Long userId) {
        refreshTokenRepository.revokeAllUserTokens(userId);
    }

    private void saveRefreshToken(Long userId, String token, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(token)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiryDate(Instant.now().plusMillis(604800000)) // 7 days
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    private RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isRevoked()) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was revoked");
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired");
        }

        return token;
    }

    private void revokeRefreshToken(String token) {
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findByToken(token);
        refreshToken.ifPresent(t -> {
            t.setRevoked(true);
            refreshTokenRepository.save(t);
        });
    }
}
