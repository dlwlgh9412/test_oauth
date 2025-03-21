package com.copago.test_oauth.auth.repository;

import com.copago.test_oauth.auth.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    @Query("select u from User u where u.email = ?1 and u.provider = ?2")
    Optional<User> findByEmailAndProvider(String email, String provider);
}
