package com.example.springsecuritydemo.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Component
public class CustomJwtRolesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String ROLE_PREFEIX = "ROLE_";
    private final String AUTHORITY_PREFEIX = "";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : getAuthorities(jwt)) {
            if (authority.startsWith("SCOPE_")) {
                grantedAuthorities.add(new SimpleGrantedAuthority(authority));
            } else {
                grantedAuthorities.add(new SimpleGrantedAuthority(this.ROLE_PREFEIX + authority));
            }
        }
        return grantedAuthorities;
    }

    private Collection<String> getAuthorities(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();
        Map<String, List<String>> realmAccess = (Map<String, List<String>>) claims.get("realm_access");
        List<String> roles = realmAccess.get("roles");
        return Collections.unmodifiableList(roles);
    }


}