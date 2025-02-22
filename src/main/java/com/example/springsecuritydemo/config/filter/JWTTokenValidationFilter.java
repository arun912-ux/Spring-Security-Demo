package com.example.springsecuritydemo.config.filter;

import com.example.springsecuritydemo.utils.JWTUtils;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
public class JWTTokenValidationFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        
        String token = request.getHeader("Authorization");

        log.info("Authorization header : {}", token);

        if (token != null && token.startsWith("Bearer ")) {

            String jwt = token.substring(7);

            try {

                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(JWTUtils.SECRET_KEY)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                String username = String.valueOf(claims.get("username"));
                String authorities = String.valueOf(claims.get("authorities"));
                String credentials = String.valueOf(claims.get("credentials"));

                log.info("username: {}, authorities: {}, credentials: {}", username, authorities, credentials);

                Authentication auth = new UsernamePasswordAuthenticationToken(username, credentials,
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));

                if (auth.isAuthenticated()) {
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }

            }
            catch (Exception e){
                log.warn("Invalid JWT token : " + e.getMessage());
//                throw new BadCredentialsException("Invalid JWT token");
            }
            
        }
        
        filterChain.doFilter(request, response);

    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        List<String> urls = List.of("/login", "/logout", "/");
        String servletPath = request.getServletPath();

        log.info("Servlet Path : {}", servletPath);

        return urls.contains(servletPath);
    }
}
