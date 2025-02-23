package com.example.springsecuritydemo.repository;

import com.example.springsecuritydemo.model.AppOAuth2User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2UserRepository extends JpaRepository<AppOAuth2User, Long> {
    AppOAuth2User findByEmail(String email);
}
