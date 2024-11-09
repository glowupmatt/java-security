package com.auth.security.resources;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldResource {
    
    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}
