package com.copago.test_oauth.auth.security;

import com.copago.test_oauth.auth.domain.user.AuthProvider;
import com.copago.test_oauth.auth.exception.OAuth2AuthenticationProcessingException;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(AuthProvider.KAKAO.toString())) {
            return new KakaoOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Login with " + registrationId + " is not supported yet.");
        }
    }
}
