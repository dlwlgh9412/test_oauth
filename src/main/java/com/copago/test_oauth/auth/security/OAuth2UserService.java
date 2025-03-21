package com.copago.test_oauth.auth.security;

import com.copago.test_oauth.auth.domain.user.AuthProvider;
import com.copago.test_oauth.auth.domain.user.Role;
import com.copago.test_oauth.auth.domain.user.User;
import com.copago.test_oauth.auth.exception.OAuth2AuthenticationProcessingException;
import com.copago.test_oauth.auth.repository.RoleRepository;
import com.copago.test_oauth.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e);
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId, oAuth2User.getAttributes());

        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();

            if (!user.getProvider().equals(AuthProvider.valueOf(registrationId.toUpperCase()))) {
                throw new OAuth2AuthenticationProcessingException(
                        "You're signed up with " + user.getProvider() + " account. " +
                                "Please use your " + user.getProvider() + " account to login.");
            }

            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        AuthProvider authProvider = AuthProvider.fromName(oAuth2UserRequest.getClientRegistration().getRegistrationId());

        String providerId = oAuth2UserInfo.getId();
        String name = oAuth2UserInfo.getName();
        String email = oAuth2UserInfo.getEmail();
        String imageUrl = oAuth2UserInfo.getImageUrl();

        User user = User.builder()
                .provider(authProvider)
                .providerId(providerId)
                .name(name)
                .email(email)
                .imageUrl(imageUrl)
                .emailVerified(true)
                .build();

        Role role = roleRepository.findByName(Role.RoleName.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Default role not found"));
        user.addRole(role);

        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oaUth2UserInfo) {
        existingUser.setName(oaUth2UserInfo.getName());
        existingUser.setImageUrl(oaUth2UserInfo.getImageUrl());
        return userRepository.save(existingUser);
    }
}
