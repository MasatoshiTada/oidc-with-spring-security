package com.example.oidcrpsample;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(OAuth2AuthenticationToken authentication, Model model) {
        Map<String, Object> attributes = authentication.getPrincipal().getAttributes();
        model.addAttribute("given_name", attributes.get("given_name"));
        model.addAttribute("family_name", attributes.get("family_name"));
        model.addAttribute("email", attributes.get("email"));
        return "index";
    }
}
