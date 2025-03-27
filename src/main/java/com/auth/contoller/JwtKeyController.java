package com.auth.contoller;


import io.jsonwebtoken.security.Keys;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.util.Base64;

@RestController
@RequestMapping("/jwt")
public class JwtKeyController {

    @GetMapping("/generate-key")
    public ResponseEntity<String> generateJwtKey() {
        // Generate a secure 256-bit key
        SecretKey key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());

        return ResponseEntity.ok("Generated Secure Key: " + base64Key);
    }
}

