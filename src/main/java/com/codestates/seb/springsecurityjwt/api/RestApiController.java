package com.codestates.seb.springsecurityjwt.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {

    @GetMapping("/rest-home")
    public String home() {
        return "home";
    }
}
