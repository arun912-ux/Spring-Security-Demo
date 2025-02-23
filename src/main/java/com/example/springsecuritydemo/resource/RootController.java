package com.example.springsecuritydemo.resource;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/")
public class RootController {


    /**
     * This is a default home page
     *
     * @return ResponseEntity<String>
     */

    @GetMapping("/")
    public ResponseEntity<?> rootHome(Authentication authentication) {
        log.info("inside rootHome");
        log.info("inside rootHome : authentication : {}", authentication);
        if (authentication != null) {
            return ResponseEntity.ok(authentication);
        }
        return ResponseEntity.ok("Hello World");
    }


    /**
     * This method is to test the @PreAuthorize annotation with hasRole
     *
     * @return String
     */

    @PreAuthorize(value = "hasRole('ADMIN')")
//    @PreAuthorize(value = "hasAnyAuthority('OIDC_USER')")
    @GetMapping({"admin"})
    public String adminHome() {
        log.info("inside admin home");
        return "Hello Admin";
    }

    @GetMapping("home")
//    @PreAuthorize(value = "hasAnyRole('USER', 'ADMIN')")
    public String home() {
        log.info("inside home");
        return "Hello Home !";
    }


    /**
     * This method is to test the Cross-Site Request Forgery (CSRF)
     *
     * @return ResponseEntity<String>
     */

    @PostMapping("/post")
    public ResponseEntity<String> post() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS))
                .body("Hello Post");
    }


    //    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @PreAuthorize(value = "hasAnyAuthority('OIDC_USER') || hasAnyRole('DEFAULT', 'ADMIN')")
    @GetMapping("/user")
    public Object user(@AuthenticationPrincipal OAuth2User oAuth2User, Authentication authentication) {
        log.info("oAuth2User : {}", oAuth2User);
        log.info("authentication : {}", authentication);
        return oAuth2User == null ? authentication : oAuth2User;
    }


}
