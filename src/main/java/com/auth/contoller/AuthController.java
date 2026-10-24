package com.auth.contoller;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.client.WeCoreAuthClient;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final WeCoreAuthClient weCoreAuthClient;

    public AuthController(WeCoreAuthClient weCoreAuthClient) {
        this.weCoreAuthClient = weCoreAuthClient;
    }

    @GetMapping
    public ResponseEntity<?> info() {
        return ResponseEntity.ok(Map.of(
                "service", "AuthService",
                "mode", "WeCoreMotorApi login proxy",
                "login", "POST /auth/login with LoginId and Password (WeCore portal user)"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody Map<String, Object> body) {
        String loginId = firstText(body, "LoginId", "username", "loginId");
        String password = firstText(body, "Password", "password");
        String reLoginKey = firstText(body, "ReLoginKey", "reLoginKey");
        if (loginId == null || password == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "LoginId and Password are required (WeCore portal user, e.g. GRPZAM)"));
        }

        Map<String, String> weCoreLogin = new LinkedHashMap<>();
        weCoreLogin.put("LoginId", loginId);
        weCoreLogin.put("Password", password);
        weCoreLogin.put("ReLoginKey", reLoginKey == null || reLoginKey.isBlank() ? "Y" : reLoginKey);

        Map<String, Object> weCoreRes = weCoreAuthClient.login(weCoreLogin);
        String token = extractToken(weCoreRes);
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(weCoreRes == null
                    ? Map.of("message", "WeCore login failed")
                    : weCoreRes);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("token", token);
        out.put("tokenType", "Bearer");
        out.put("loginId", loginId);
        out.put("source", "WeCoreMotorApi");
        out.put("Result", weCoreRes == null ? null : weCoreRes.get("Result"));
        out.put("Message", weCoreRes == null ? "Success" : weCoreRes.get("Message"));
        return ResponseEntity.ok(out);
    }

    private String firstText(Map<String, Object> body, String... keys) {
        for (String key : keys) {
            Object value = body.get(key);
            if (value != null && !value.toString().isBlank()) {
                return value.toString();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String extractToken(Map<String, Object> response) {
        if (response == null) {
            return null;
        }
        Object result = response.get("Result");
        if (result instanceof Map<?, ?> resultMap) {
            Object token = resultMap.get("Token");
            if (token != null && !token.toString().isBlank()) {
                return token.toString();
            }
        }
        Object token = response.get("Token");
        return token == null ? null : token.toString();
    }
}
