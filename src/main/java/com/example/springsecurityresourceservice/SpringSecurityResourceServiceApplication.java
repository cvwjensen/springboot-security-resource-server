package com.example.springsecurityresourceservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.security.Security;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@SpringBootApplication
@RestController
@EnableWebSecurity
public class SpringSecurityResourceServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityResourceServiceApplication.class, args);
    }

    @GetMapping("/public")
    public String helloPublic() {
        return "Hello, " + SecurityContextHolder.getContext().getAuthentication() + "!";
    }

    @GetMapping("/private")
    public String hello() {
        return "Hello, " + SecurityContextHolder.getContext().getAuthentication() + "!";
    }

    @GetMapping("/user/authorities")
    public Map<String,Object> getPrincipalInfo(JwtAuthenticationToken principal) {

        Collection<String> authorities = principal.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String,Object> info = new HashMap<>();
        info.put("name", principal.getName());
        info.put("authorities", authorities);
        info.put("tokenAttributes", principal.getTokenAttributes());

        return info;
    }

    @Bean
    //    https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
//                Authorization section - for all requests...
                .authorizeHttpRequests(authorize -> authorize
                        // For any path starting with /user/... the user must have the SCOPE_profile authority
                        .requestMatchers("/user/**").hasAuthority("SCOPE_profile")
                        // For any other request, no authorization is required - thereby making it public
                        .anyRequest().permitAll()
                )
                // I want to add Oauth authentication filter to the filter chain. And I expect AccessTokens to be JWTs
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));;
        return http.build();
    }


}

