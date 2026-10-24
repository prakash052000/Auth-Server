package com.auth.contoller;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public Map<String, String> home() {
        return Map.of(
                "service", "AUTH-SERVICE",
                "status", "UP",
                "login", "POST /auth/login",
                "register", "POST /auth/register",
                "health", "GET /actuator/health");
    }
}
