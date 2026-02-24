package com.userid.api.client;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.server.ResponseStatusException;

@Component
public class SocialProviderOAuthClient {
  private static final Logger log = LoggerFactory.getLogger(SocialProviderOAuthClient.class);

  private static final String GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
  private static final String GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo";
  private static final String YANDEX_TOKEN_ENDPOINT = "https://oauth.yandex.com/token";
  private static final String YANDEX_USERINFO_ENDPOINT = "https://login.yandex.ru/info?format=json";
  private static final String VK_TOKEN_ENDPOINT = "https://id.vk.ru/oauth2/auth";
  private static final String VK_USERINFO_ENDPOINT = "https://id.vk.ru/oauth2/user_info";

  private final RestClient restClient = RestClient.builder().build();

  public SocialPrincipalDTO resolvePrincipal(
      AuthServerSocialProviderEnum provider,
      SocialProviderAuthConfigDTO config,
      AuthServerSocialLoginRequestDTO request
  ) {
    if (provider == null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider is required");
    }
    if (config == null) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social provider config is required");
    }
    if (request == null || !StringUtils.hasText(request.code())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Social auth code is required");
    }

    return switch (provider) {
      case GOOGLE -> resolveGooglePrincipal(config, request.code().trim());
      case YANDEX -> resolveYandexPrincipal(config, request.code().trim());
      case VK -> resolveVkPrincipal(config, request);
    };
  }

  private SocialPrincipalDTO resolveGooglePrincipal(SocialProviderAuthConfigDTO config, String code) {
    requireConfig(config, "Google social provider is not configured");

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("code", code);
    form.add("client_id", config.clientId());
    form.add("client_secret", config.clientSecret());
    form.add("redirect_uri", config.callbackUri());
    form.add("grant_type", "authorization_code");

    GoogleTokenResponseDTO tokenResponse;
    try {
      tokenResponse = restClient.post()
          .uri(GOOGLE_TOKEN_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(form)
          .retrieve()
          .body(GoogleTokenResponseDTO.class);
    } catch (RestClientException ex) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Google authorization code");
    }

    if (tokenResponse == null || !StringUtils.hasText(tokenResponse.accessToken())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Google token response is invalid");
    }

    GoogleUserInfoDTO userInfo;
    try {
      userInfo = restClient.get()
          .uri(GOOGLE_USERINFO_ENDPOINT)
          .headers(headers -> headers.setBearerAuth(tokenResponse.accessToken()))
          .retrieve()
          .body(GoogleUserInfoDTO.class);
    } catch (RestClientException ex) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to resolve Google user profile");
    }

    String subject = userInfo == null ? null : trimToNull(userInfo.sub());
    String email = userInfo == null ? null : normalizeEmail(userInfo.email());
    boolean emailVerified = userInfo != null && Boolean.TRUE.equals(userInfo.emailVerified());
    if (!StringUtils.hasText(subject) || !StringUtils.hasText(email)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Google user profile is incomplete");
    }
    if (!emailVerified) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Google email is not verified");
    }

    return new SocialPrincipalDTO(subject, email, true);
  }

  private SocialPrincipalDTO resolveYandexPrincipal(SocialProviderAuthConfigDTO config, String code) {
    requireConfig(config, "Yandex social provider is not configured");

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code", code);
    form.add("client_id", config.clientId());
    form.add("client_secret", config.clientSecret());
    form.add("redirect_uri", config.callbackUri());

    YandexTokenResponseDTO tokenResponse;
    try {
      tokenResponse = restClient.post()
          .uri(YANDEX_TOKEN_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(form)
          .retrieve()
          .body(YandexTokenResponseDTO.class);
    } catch (RestClientResponseException ex) {
      String body = ex.getResponseBodyAsString();
      if (body != null && body.toLowerCase().contains("invalid_client")) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Yandex OAuth client config is invalid");
      }
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "Invalid Yandex authorization code or redirect_uri mismatch");
    } catch (RestClientException ex) {
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "Invalid Yandex authorization code or redirect_uri mismatch");
    }

    if (tokenResponse == null || !StringUtils.hasText(tokenResponse.accessToken())) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Yandex token response is invalid");
    }

    YandexUserInfoDTO userInfo;
    try {
      userInfo = restClient.get()
          .uri(YANDEX_USERINFO_ENDPOINT)
          .headers(headers -> headers.set("Authorization", "OAuth " + tokenResponse.accessToken()))
          .retrieve()
          .body(YandexUserInfoDTO.class);
    } catch (RestClientException ex) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to resolve Yandex user profile");
    }

    String subject = userInfo == null ? null : trimToNull(userInfo.id());
    String email = userInfo == null ? null : normalizeEmail(userInfo.defaultEmail());
    if (!StringUtils.hasText(email) && userInfo != null && userInfo.emails() != null) {
      email = userInfo.emails().stream()
          .map(this::normalizeEmail)
          .filter(StringUtils::hasText)
          .findFirst()
          .orElse(null);
    }
    if (!StringUtils.hasText(subject) || !StringUtils.hasText(email)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Yandex user profile is incomplete");
    }

    return new SocialPrincipalDTO(subject, email, true);
  }

  private SocialPrincipalDTO resolveVkPrincipal(SocialProviderAuthConfigDTO config, AuthServerSocialLoginRequestDTO request) {
    requireConfig(config, "VK social provider is not configured");
    String codeVerifier = trimToNull(request.codeVerifier());
    String deviceId = trimToNull(request.deviceId());
    String state = trimToNull(request.state());
    if (!StringUtils.hasText(codeVerifier) || !StringUtils.hasText(deviceId)) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "VK auth payload is incomplete");
    }

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code_verifier", codeVerifier);
    form.add("redirect_uri", config.callbackUri());
    form.add("code", request.code().trim());
    form.add("client_id", config.clientId());
    form.add("device_id", deviceId);
    if (StringUtils.hasText(state)) {
      form.add("state", state);
    }

    VkTokenResponseDTO tokenResponse;
    try {
      tokenResponse = restClient.post()
          .uri(VK_TOKEN_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(form)
          .retrieve()
          .body(VkTokenResponseDTO.class);
    } catch (RestClientException ex) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid VK authorization code");
    }

    if (tokenResponse == null
        || !StringUtils.hasText(tokenResponse.accessToken())
        || tokenResponse.userId() == null) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "VK token response is invalid");
    }

    MultiValueMap<String, String> userInfoForm = new LinkedMultiValueMap<>();
    userInfoForm.add("client_id", config.clientId());
    userInfoForm.add("access_token", tokenResponse.accessToken());

    VkUserInfoResponseDTO userInfoResponse;
    try {
      userInfoResponse = restClient.post()
          .uri(VK_USERINFO_ENDPOINT)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(userInfoForm)
          .retrieve()
          .body(VkUserInfoResponseDTO.class);
    } catch (RestClientException ex) {
      log.warn("VK userinfo failed reason={}", ex.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to resolve VK user profile");
    }

    Long subjectUserId = tokenResponse.userId();
    String email = null;
    if (userInfoResponse != null && userInfoResponse.user() != null) {
      if (userInfoResponse.user().userId() != null) {
        subjectUserId = userInfoResponse.user().userId();
      }
      email = normalizeEmail(userInfoResponse.user().email());
    }

    if (!StringUtils.hasText(email)) {
      throw new ResponseStatusException(
          HttpStatus.UNAUTHORIZED,
          "VK email is unavailable. Add email scope in VK app settings");
    }

    return new SocialPrincipalDTO(String.valueOf(subjectUserId), email, true);
  }

  private void requireConfig(SocialProviderAuthConfigDTO config, String message) {
    if (!StringUtils.hasText(config.clientId())
        || !StringUtils.hasText(config.clientSecret())
        || !StringUtils.hasText(config.callbackUri())) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
  }

  private String trimToNull(String value) {
    if (!StringUtils.hasText(value)) {
      return null;
    }
    return value.trim();
  }

  private String normalizeEmail(String value) {
    return EmailNormalizer.normalizeNullable(value);
  }

  public record SocialProviderAuthConfigDTO(
      String clientId,
      String clientSecret,
      String callbackUri
  ) {
  }

  public record SocialPrincipalDTO(
      String subject,
      String email,
      boolean emailVerified
  ) {
  }

  private record GoogleTokenResponseDTO(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token")
      String accessToken
  ) {
  }

  private record GoogleUserInfoDTO(
      String sub,
      String email,
      @com.fasterxml.jackson.annotation.JsonProperty("email_verified")
      Boolean emailVerified
  ) {
  }

  private record YandexTokenResponseDTO(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token")
      String accessToken
  ) {
  }

  private record YandexUserInfoDTO(
      String id,
      @com.fasterxml.jackson.annotation.JsonProperty("default_email")
      String defaultEmail,
      List<String> emails
  ) {
  }

  private record VkTokenResponseDTO(
      @com.fasterxml.jackson.annotation.JsonProperty("access_token")
      String accessToken,
      @com.fasterxml.jackson.annotation.JsonProperty("id_token")
      String idToken,
      @com.fasterxml.jackson.annotation.JsonProperty("user_id")
      Long userId
  ) {
  }

  private record VkUserInfoResponseDTO(
      VkUserInfoDTO user
  ) {
  }

  private record VkUserInfoDTO(
      @com.fasterxml.jackson.annotation.JsonProperty("user_id")
      Long userId,
      String email
  ) {
  }
}
