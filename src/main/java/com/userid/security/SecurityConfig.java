package com.userid.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
  private final JwtAuthenticationFilter jwtAuthenticationFilter;

  public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/auth/confirm").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/forgot-password").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/reset-password").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/domains/*/users/login").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/domains/*/users/confirm").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/domains/*/users/forgot-password").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/domains/*/users/reset-password").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/domains/*/users/resend-verification").permitAll()
            .requestMatchers(HttpMethod.PUT, "/api/domains/*/users/me").permitAll()
            .anyRequest().authenticated()
        )
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}
