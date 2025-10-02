package com.example.springsecuritydemo.resource;


import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.concurrent.TimeUnit;

@Slf4j
@DenyAll
@RestController
@RequestMapping("api")
public class RootController {

    @PermitAll
    @GetMapping("logclaims")
    public ResponseEntity<?> logJwtClaims(@AuthenticationPrincipal Jwt jwt, Authentication authentication) {
        log.info("Authentication principal is {}", authentication);
        if (authentication != null) {
            log.info("Authentication Authorities are {}", authentication.getAuthorities());
        }
        if (jwt == null) {
            log.warn("JWT principal is null");
            return ResponseEntity.ok("No JWT available");
        }

        // Log all claims
        log.info("JWT Claims: {}", jwt.getClaims());
//        jwt.getClaims().forEach((key, value) -> log.info("JWT Claim - {} : {}", key, value));

        return ResponseEntity.ok(jwt.getClaims());
    }

    /**
     * This is a default home page
     *
     * @return ResponseEntity<String>
     */

    @PermitAll
    @GetMapping
    public ResponseEntity<?> rootHome(@AuthenticationPrincipal Principal principal, Authentication authentication) {
        log.info("Principal : {}", principal);
        log.info("Authentication : {}", authentication);
        log.info("inside rootHome");
        return ResponseEntity.ok("Hello World");
    }


    /**
     * This method is to test the @PreAuthorize annotation with hasRole
     *
     * @return String
     */

//    @PreAuthorize(value = "hasAnyRole('USER', 'ADMIN')")
    @GetMapping({"admin"})
    @RolesAllowed({"READ_WRITE"})
//    @PreAuthorize("hasAnyAuthority('READ_WRITE', 'READ_ONLY')")
    public String adminHome(Authentication authentication) {
        log.info("inside admin home");
        if (authentication != null) {
            log.info("Authentication Authorities : {}", authentication.getAuthorities());
        }
        return "Hello Admin";
    }

    @GetMapping("home")
//    @PreAuthorize(value = "hasAnyRole('USER', 'ADMIN')")
    @RolesAllowed({"READ_ONLY", "READ_WRITE"})
    public String home() {
        log.info("inside home");
        return "Hello Home !";
    }


    /**
     * This method is to test the Cross-Site Request Forgery (CSRF)
     *
     * @return ResponseEntity<String>
     */
    @PermitAll
    @PostMapping("post")
    public ResponseEntity<String> post() {
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS)).body("Hello Post");
    }


    //    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PreAuthorize("hasAnyRole('READ_WRITE', 'READ_ONLY')")
    @GetMapping("user")
    public Object user(Authentication authentication) {
        log.info("authentication : {}", authentication);
        Principal principal = (Principal) authentication.getPrincipal();
        return authentication;
    }

}
