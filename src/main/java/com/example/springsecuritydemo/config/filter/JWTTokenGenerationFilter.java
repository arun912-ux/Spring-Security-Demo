package com.example.springsecuritydemo.config.filter;

import com.example.springsecuritydemo.utils.JWTUtils;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JWTTokenGenerationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("Auth Object : {}", auth);

        if (auth != null && auth.isAuthenticated()) {

            Date currentDate = new Date();
            String jwt = Jwts.builder()
                            .setIssuer("Spring Security").setSubject("JWT")
                            .claim("username", auth.getName())
                            .claim("authorities", commaSeparatedAuthorities(auth.getAuthorities()))
//                            no point in getting credentials. It won't be printed anyway
//                            .claim("credentials", auth.getCredentials())
                            .setIssuedAt(currentDate)
                            .setExpiration(new Date(currentDate.getTime() + 60000L))
                            .signWith(JWTUtils.SECRET_KEY).compact();

            log.info("JWT Token generated : {}", jwt);

            String token = "Bearer " + jwt;

            response.setHeader("Authorization", token);
        }
        filterChain.doFilter(request, response);
    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        List<String> urls = List.of("/login", "/logout", "/");

        String servletPath = request.getServletPath();
        log.info("Servlet Path : {}", servletPath);
        return !urls.contains(servletPath);
    }





    private String commaSeparatedAuthorities(Collection<? extends GrantedAuthority> authorities){
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", "));
    }

}

