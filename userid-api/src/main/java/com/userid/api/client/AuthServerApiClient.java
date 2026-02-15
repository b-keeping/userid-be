package com.userid.api.client;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

@RequiredArgsConstructor
public class AuthServerApiClient {
  private static final Pattern MESSAGE_PATTERN =
      Pattern.compile("\\\"message\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

  private final RestTemplate restTemplate;
  private final AuthServerApiProperties properties;

  public void register(AuthServerRegisterRequest request) {
    if (!properties.isEnabled()) {
      return;
    }

    requireConfigured();

    String endpoint = "%s%s".formatted(
        normalizeBaseUrl(properties.getBaseUrl()),
        UseridApiEndpoints.externalDomainUsers(properties.getDomainId()));

    try {
      restTemplate.exchange(
          endpoint,
          HttpMethod.POST,
          new HttpEntity<>(request, requestHeaders()),
          Void.class);
    } catch (HttpStatusCodeException ex) {
      throw mapStatusException(ex, "Registration failed on auth server");
    } catch (ResourceAccessException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration server is unavailable");
    }
  }

  public void confirm(String code) {
    if (!properties.isEnabled()) {
      return;
    }

    requireConfigured();

    String endpoint = "%s%s".formatted(
        normalizeBaseUrl(properties.getBaseUrl()),
        UseridApiEndpoints.externalDomainUsersConfirm(properties.getDomainId()));

    try {
      restTemplate.exchange(
          endpoint,
          HttpMethod.POST,
          new HttpEntity<>(new AuthServerConfirmRequest(code), requestHeaders()),
          Void.class);
    } catch (HttpStatusCodeException ex) {
      throw mapStatusException(ex, "Confirmation failed on auth server");
    } catch (ResourceAccessException ex) {
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration server is unavailable");
    }
  }

  private HttpHeaders requestHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.setBearerAuth(properties.getApiToken().trim());
    return headers;
  }

  private String normalizeBaseUrl(String baseUrl) {
    String trimmed = baseUrl.trim();
    if (trimmed.endsWith("/")) {
      return trimmed.substring(0, trimmed.length() - 1);
    }
    return trimmed;
  }

  private void requireConfigured() {
    if (!StringUtils.hasText(properties.getBaseUrl())
        || properties.getDomainId() == null
        || !StringUtils.hasText(properties.getApiToken())) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Auth server is not configured");
    }
  }

  private ResponseStatusException mapStatusException(
      HttpStatusCodeException ex,
      String fallbackMessage
  ) {
    String message = fallbackMessage;
    String body = ex.getResponseBodyAsString();
    if (StringUtils.hasText(body)) {
      Matcher matcher = MESSAGE_PATTERN.matcher(body);
      if (matcher.find() && StringUtils.hasText(matcher.group(1))) {
        message = matcher.group(1);
      }
    }
    return new ResponseStatusException(ex.getStatusCode(), message);
  }
}
