package com.userid.security;

import com.userid.api.client.UseridApiEndpoints;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
public class SecurityConfig {
  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final DomainApiAuthenticationFilter domainApiAuthenticationFilter;

  public SecurityConfig(
      JwtAuthenticationFilter jwtAuthenticationFilter,
      DomainApiAuthenticationFilter domainApiAuthenticationFilter
  ) {
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    this.domainApiAuthenticationFilter = domainApiAuthenticationFilter;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint((request, response, authException) -> {
              log.warn("Unauthorized method={} path={} message={}",
                  request.getMethod(), request.getRequestURI(), authException.getMessage());
              response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            })
            .accessDeniedHandler((request, response, accessDeniedException) -> {
              log.warn("Access denied method={} path={} message={}",
                  request.getMethod(), request.getRequestURI(), accessDeniedException.getMessage());
              response.sendError(HttpServletResponse.SC_FORBIDDEN);
            })
        )
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/error").permitAll()
            .requestMatchers(
                HttpMethod.PUT,
                UseridApiEndpoints.EXTERNAL_DOMAIN_USERS_WILDCARD_BASE + UseridApiEndpoints.ME)
            .permitAll()
            .requestMatchers(
                UseridApiEndpoints.EXTERNAL_DOMAIN_USERS_WILDCARD_BASE + UseridApiEndpoints.ALL_SUBPATHS)
            .hasRole("DOMAIN_API")
            .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/login/social").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/register/social").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/auth/confirm").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/auth/social/*/config").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/forgot-password").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/reset-password").permitAll()
            .anyRequest().authenticated()
        )
        .addFilterBefore(domainApiAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}
