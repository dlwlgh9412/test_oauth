package com.copago.test_oauth.auth.controller;

import com.copago.test_oauth.auth.dto.UpdateUserRequest;
import com.copago.test_oauth.auth.dto.UserResponse;
import com.copago.test_oauth.auth.security.CurrentUser;
import com.copago.test_oauth.auth.security.UserPrincipal;
import com.copago.test_oauth.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserResponse> getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return ResponseEntity.ok(
                userService.getUserById(userPrincipal.getId())
        );
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(
                userService.getUserById(id)
        );
    }

    @PutMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserResponse> updateUser(@CurrentUser UserPrincipal userPrincipal,
                                                   @Valid @RequestBody UpdateUserRequest updateRequest) {
        return ResponseEntity.ok(
                userService.updateUser(userPrincipal, updateRequest)
        );
    }
}
