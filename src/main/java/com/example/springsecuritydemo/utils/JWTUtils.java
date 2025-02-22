package com.example.springsecuritydemo.utils;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public final class JWTUtils {


    public static final String JWT_KEY = "M15OhUnnF76P!@#$%^&*()vv8R&%^R%rv%&r8v7B^Vr75d57vCE58v*4ec7Evr5**86%FCE4v76g2UUqrB7lz" +
                                        "tM15OhUnnF!@#$%^&*()vv8R&%^R%rv%&r8v7B^Vr75d57vCE58v*4ec7Evr5**86%FCE4v76Pg2UUqrB7lq6H91uh1kq6H91uh1";

    public static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(JWT_KEY.getBytes(StandardCharsets.UTF_8));


    private JWTUtils() {
    }
}
