package com.example.springsecuritydemo.resource;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

@Slf4j
@RestController
@RequestMapping("/")
public class RootController {


    /**
     *
     * This is a default home page
     *
     * @return ResponseEntity<String>
     */

    @GetMapping("/")
    public ResponseEntity<String> rootHome(){
        Logger.getLogger(RootController.class.getName()).log(Level.INFO, "inside home");
        return ResponseEntity.ok("Hello World");
    }


    /**
     * This method is to test the @PreAuthorize annotation with hasRole
     *
     * @return String
     */

    @PreAuthorize(value = "hasAnyRole('USER', 'ADMIN')")
    @GetMapping({"admin", "admin/"})
    public String adminHome(){
        log.info("inside admin home");
        return "Hello Admin";
    }

    @GetMapping("/home")
    @PreAuthorize(value = "hasAnyRole('USER', 'ADMIN')")
    public String home(){
        log.info("inside home");
        return "Hello Home !";
    }


    /**
     *
     * This method is to test the Cross-Site Request Forgery (CSRF)
     *
     * @return ResponseEntity<String>
     */

    @PostMapping("/post")
    public ResponseEntity<String> post(){
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS))
                .body("Hello Post");
    }



    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/user")
    public Object user(Authentication authentication){
        log.info("authentication : {}", authentication);
//        Principal principal = (Principal) authentication.getPrincipal();
        return authentication;
    }



}
