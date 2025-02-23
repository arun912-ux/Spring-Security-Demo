package com.example.springsecuritydemo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
public class CustomOidcUserService extends OidcUserService {
    /**
     * @param userRequest the user request
     * @return
     * @throws OAuth2AuthenticationException
     */
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        log.info("CustomOidcUserService.loadUser : oidcUser : {}", oidcUser);
        Map<String, Object> attributes = oidcUser.getAttributes();
        log.info("CustomOidcUserService.loadUser : attributes : {}", attributes);
        Map<String, Object> claims = oidcUser.getClaims();
        log.info("CustomOidcUserService.loadUser : claims : {}", claims);
        OidcUserInfo userInfo = oidcUser.getUserInfo();
        log.info("CustomOidcUserService.loadUser : userInfo : {}", userInfo);
        return oidcUser;
    }
}
