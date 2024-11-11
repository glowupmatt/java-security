package com.auth.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class JwtAuthenticationResource {


    @PostMapping("/authenticate")
    public Authentication authenticate(Authentication authentication) {
        return authentication;
    }
    
}
