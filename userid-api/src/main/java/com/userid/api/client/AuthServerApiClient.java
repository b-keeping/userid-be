package com.userid.api.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class AuthServerApiClient {
  private static final Pattern MESSAGE_PATTERN =
      Pattern.compile("\\\"message\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

  private final RestTemplate restTemplate;
  private final AuthServerApiProperties properties;
  private final ObjectMapper objectMapper;
  private final UseridApiMessageResolver messageResolver;

  public boolean isEnabled() {
    return properties.isEnabled();
  }

  public void register(AuthServerRegisterRequest request) {
    if (!properties.isEnabled()) {
      return;
    }

    requireConfigured();

    String endpoint = "%s%s".formatted(
        normalizeBaseUrl(properties.getBaseUrl()),
        UseridApiEndpoints.externalDomainUsers(properties.getDomainId()));
    int valuesCount = request.values() == null ? 0 : request.values().size();
    log.info(
        "Auth server register start url={} domainId={} email={} valuesCount={}",
        endpoint,
        properties.getDomainId(),
        request.email(),
        valuesCount);

    try {
      restTemplate.exchange(
          endpoint,
          HttpMethod.POST,
          new HttpEntity<>(request, requestHeaders()),
          Void.class);
      log.info(
          "Auth server register success domainId={} email={}",
          properties.getDomainId(),
          request.email());
    } catch (HttpStatusCodeException ex) {
      ResponseStatusException mapped = mapStatusException(ex, "Registration failed on auth server");
      log.warn(
          "Auth server register failed domainId={} email={} status={} message={}",
          properties.getDomainId(),
          request.email(),
          ex.getStatusCode(),
          mapped.getReason());
      throw mapped;
    } catch (ResourceAccessException ex) {
      log.warn(
          "Auth server register failed domainId={} email={} reason={}",
          properties.getDomainId(),
          request.email(),
          ex.getMessage());
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
    int codeLength = code == null ? 0 : code.length();
    log.info(
        "Auth server confirm start url={} domainId={} codeLength={}",
        endpoint,
        properties.getDomainId(),
        codeLength);

    try {
      restTemplate.exchange(
          endpoint,
          HttpMethod.POST,
          new HttpEntity<>(new AuthServerConfirmRequest(code), requestHeaders()),
          Void.class);
      log.info("Auth server confirm success domainId={} codeLength={}", properties.getDomainId(), codeLength);
    } catch (HttpStatusCodeException ex) {
      ResponseStatusException mapped = mapStatusException(ex, "Confirmation failed on auth server");
      log.warn(
          "Auth server confirm failed domainId={} status={} message={}",
          properties.getDomainId(),
          ex.getStatusCode(),
          mapped.getReason());
      throw mapped;
    } catch (ResourceAccessException ex) {
      log.warn(
          "Auth server confirm failed domainId={} reason={}",
          properties.getDomainId(),
          ex.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration server is unavailable");
    }
  }

  public AuthServerLoginResponse login(AuthServerLoginRequest request) {
    if (!properties.isEnabled()) {
      return null;
    }

    requireConfigured();

    String endpoint = "%s%s".formatted(
        normalizeBaseUrl(properties.getBaseUrl()),
        UseridApiEndpoints.externalDomainUsersLogin(properties.getDomainId()));
    log.info(
        "Auth server login start url={} domainId={} email={}",
        endpoint,
        properties.getDomainId(),
        request.email());

    try {
      AuthServerLoginResponse response = restTemplate.exchange(
              endpoint,
              HttpMethod.POST,
              new HttpEntity<>(request, requestHeaders()),
              AuthServerLoginResponse.class)
          .getBody();
      log.info(
          "Auth server login success domainId={} email={} hasToken={}",
          properties.getDomainId(),
          request.email(),
          response != null && StringUtils.hasText(response.token()));
      return response;
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().value() == HttpStatus.UNAUTHORIZED.value()) {
        String localizedMessage = messageResolver.loginUnauthorizedMessage();
        log.warn(
            "Auth server login failed domainId={} email={} status={} message={}",
            properties.getDomainId(),
            request.email(),
            ex.getStatusCode(),
            localizedMessage);
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, localizedMessage);
      }
      ResponseStatusException mapped = mapStatusException(ex, "Login failed on auth server");
      log.warn(
          "Auth server login failed domainId={} email={} status={} message={}",
          properties.getDomainId(),
          request.email(),
          ex.getStatusCode(),
          mapped.getReason());
      throw mapped;
    } catch (ResourceAccessException ex) {
      log.warn(
          "Auth server login failed domainId={} email={} reason={}",
          properties.getDomainId(),
          request.email(),
          ex.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration server is unavailable");
    }
  }

  public void forgotPassword(AuthServerForgotPasswordRequest request) {
    if (!properties.isEnabled()) {
      return;
    }

    requireConfigured();

    String endpoint = "%s%s".formatted(
        normalizeBaseUrl(properties.getBaseUrl()),
        UseridApiEndpoints.externalDomainUsersForgotPassword(properties.getDomainId()));
    log.info(
        "Auth server forgot-password start url={} domainId={} email={}",
        endpoint,
        properties.getDomainId(),
        request.email());

    try {
      restTemplate.exchange(
          endpoint,
          HttpMethod.POST,
          new HttpEntity<>(request, requestHeaders()),
          Void.class);
      log.info(
          "Auth server forgot-password success domainId={} email={}",
          properties.getDomainId(),
          request.email());
    } catch (HttpStatusCodeException ex) {
      ResponseStatusException mapped = mapStatusException(ex, "Forgot password failed on auth server");
      log.warn(
          "Auth server forgot-password failed domainId={} email={} status={} message={}",
          properties.getDomainId(),
          request.email(),
          ex.getStatusCode(),
          mapped.getReason());
      throw mapped;
    } catch (ResourceAccessException ex) {
      log.warn(
          "Auth server forgot-password failed domainId={} email={} reason={}",
          properties.getDomainId(),
          request.email(),
          ex.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration server is unavailable");
    }
  }

  public void resetPassword(AuthServerResetPasswordRequest request) {
    if (!properties.isEnabled()) {
      return;
    }

    requireConfigured();

    String endpoint = "%s%s".formatted(
        normalizeBaseUrl(properties.getBaseUrl()),
        UseridApiEndpoints.externalDomainUsersResetPassword(properties.getDomainId()));
    int codeLength = request.code() == null ? 0 : request.code().length();
    log.info(
        "Auth server reset-password start url={} domainId={} codeLength={}",
        endpoint,
        properties.getDomainId(),
        codeLength);

    try {
      restTemplate.exchange(
          endpoint,
          HttpMethod.POST,
          new HttpEntity<>(request, requestHeaders()),
          Void.class);
      log.info(
          "Auth server reset-password success domainId={} codeLength={}",
          properties.getDomainId(),
          codeLength);
    } catch (HttpStatusCodeException ex) {
      ResponseStatusException mapped = mapStatusException(ex, "Reset password failed on auth server");
      log.warn(
          "Auth server reset-password failed domainId={} status={} message={}",
          properties.getDomainId(),
          ex.getStatusCode(),
          mapped.getReason());
      throw mapped;
    } catch (ResourceAccessException ex) {
      log.warn(
          "Auth server reset-password failed domainId={} reason={}",
          properties.getDomainId(),
          ex.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration server is unavailable");
    }
  }

  public void updateSelf(String userJwtToken, AuthServerUserSelfUpdateRequest request) {
    if (!properties.isEnabled()) {
      return;
    }

    requireConfigured();

    if (!StringUtils.hasText(userJwtToken)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing external user token");
    }

    String endpoint = "%s%s".formatted(
        normalizeBaseUrl(properties.getBaseUrl()),
        UseridApiEndpoints.externalDomainUsersMe(properties.getDomainId()));
    int valuesCount = request.values() == null ? 0 : request.values().size();
    boolean passwordProvided = StringUtils.hasText(request.password());
    log.info(
        "Auth server user update start url={} domainId={} valuesCount={} passwordProvided={}",
        endpoint,
        properties.getDomainId(),
        valuesCount,
        passwordProvided);

    try {
      restTemplate.exchange(
          endpoint,
          HttpMethod.PUT,
          new HttpEntity<>(request, userJwtHeaders(userJwtToken)),
          Void.class);
      log.info(
          "Auth server user update success domainId={} valuesCount={} passwordProvided={}",
          properties.getDomainId(),
          valuesCount,
          passwordProvided);
    } catch (HttpStatusCodeException ex) {
      ResponseStatusException mapped = mapStatusException(ex, "User update failed on auth server");
      log.warn(
          "Auth server user update failed domainId={} status={} message={}",
          properties.getDomainId(),
          ex.getStatusCode(),
          mapped.getReason());
      throw mapped;
    } catch (ResourceAccessException ex) {
      log.warn(
          "Auth server user update failed domainId={} reason={}",
          properties.getDomainId(),
          ex.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration server is unavailable");
    }
  }

  private String toJson(Object payload) {
    try {
      return objectMapper.writeValueAsString(payload);
    } catch (JsonProcessingException ex) {
      log.warn("Failed to serialize auth server payload", ex);
      return "<serialization-error>";
    }
  }

  private HttpHeaders requestHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.setBearerAuth(properties.getApiToken().trim());
    return headers;
  }

  private HttpHeaders userJwtHeaders(String userJwtToken) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.setBearerAuth(userJwtToken.trim());
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
