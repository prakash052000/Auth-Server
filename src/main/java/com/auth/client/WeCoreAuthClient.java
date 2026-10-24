package com.auth.client;

import java.util.Map;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "WeCoreMotorApi")
public interface WeCoreAuthClient {

    @PostMapping("/authentication/login")
    Map<String, Object> login(@RequestBody Map<String, String> body);
}
