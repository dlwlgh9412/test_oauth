package com.copago.test_oauth.auth.service;

import com.copago.test_oauth.auth.domain.user.User;
import com.copago.test_oauth.auth.dto.UpdateUserRequest;
import com.copago.test_oauth.auth.dto.UserResponse;
import com.copago.test_oauth.auth.exception.ResourceNotFoundException;
import com.copago.test_oauth.auth.repository.UserRepository;
import com.copago.test_oauth.auth.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#id")
    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));

        return UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .imageUrl(user.getImageUrl())
                .provider(user.getProvider())
                .build();
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "users", key = "#email")
    public UserResponse getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));

        return UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .imageUrl(user.getImageUrl())
                .provider(user.getProvider())
                .build();
    }

    @Transactional
    @CacheEvict(value = "users", key = "#userPrincipal.id")
    public UserResponse updateUser(UserPrincipal userPrincipal, UpdateUserRequest updateRequest) {
        User user = userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));

        // 현재 인증된 사용자의 정보만 수정 가능
        if (!user.getId().equals(userPrincipal.getId())) {
            throw new AccessDeniedException("You don't have permission to update this user");
        }

        user.setName(updateRequest.getName());
        if (updateRequest.getImageUrl() != null) {
            user.setImageUrl(updateRequest.getImageUrl());
        }

        User updatedUser = userRepository.save(user);

        return UserResponse.builder()
                .id(updatedUser.getId())
                .name(updatedUser.getName())
                .email(updatedUser.getEmail())
                .imageUrl(updatedUser.getImageUrl())
                .provider(updatedUser.getProvider())
                .build();
    }
}
