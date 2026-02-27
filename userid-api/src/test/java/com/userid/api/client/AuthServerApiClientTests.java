package com.userid.api.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

class AuthServerApiClientTests {
  private RestTemplate restTemplate;
  private AuthServerApiProperties properties;
  private AuthServerApiClient authServerApiClient;
  private MockRestServiceServer server;

  @BeforeEach
  void setUp() {
    restTemplate = new RestTemplate();
    properties = new AuthServerApiProperties();
    properties.setEnabled(true);
    properties.setBaseUrl("https://auth.example.org");
    properties.setDomainId(55L);
    properties.setApiToken("domain-token");
    properties.setLanguage(UseridApiLanguageEnum.RU);
    authServerApiClient =
        new AuthServerApiClient(
            restTemplate,
            properties,
            new UseridApiMessageResolver(properties));
    server = MockRestServiceServer.bindTo(restTemplate).build();
  }

  @Test
  void registerSendsExpectedPayload() {
    server.expect(requestTo("https://auth.example.org/api/external/domains/55/users"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer domain-token"))
        .andExpect(jsonPath("$.email").value("user@example.org"))
        .andExpect(jsonPath("$.password").value("secret"))
        .andExpect(jsonPath("$.values[0].fieldId").value(12))
        .andExpect(jsonPath("$.values[0].name").value("Фамилия"))
        .andExpect(jsonPath("$.values[0].stringValue").value("Иванов"))
        .andExpect(jsonPath("$.values[5].fieldId").value(17))
        .andExpect(jsonPath("$.values[5].dateValue").value("1990-01-15"))
        .andExpect(jsonPath("$.values[6].fieldId").value(21))
        .andExpect(jsonPath("$.values[6].numericValue").value("37360000000"))
        .andRespond(withSuccess());

    authServerApiClient.register(registerRequest());

    server.verify();
  }

  @Test
  void confirmCallsDomainEndpointWithCodeBody() {
    server.expect(requestTo("https://auth.example.org/api/external/domains/55/users/confirm"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer domain-token"))
        .andExpect(jsonPath("$.code").value("abc123"))
        .andRespond(withSuccess());

    authServerApiClient.confirm("abc123");

    server.verify();
  }

  @Test
  void loginCallsDomainEndpointAndReturnsPayload() {
    server.expect(requestTo("https://auth.example.org/api/external/domains/55/users/login"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer domain-token"))
        .andExpect(jsonPath("$.email").value("user@example.org"))
        .andExpect(jsonPath("$.password").value("secret"))
        .andRespond(withSuccess("""
            {
              "token": "user-jwt-token",
              "user": {
                "id": 101,
                "email": "user@example.org",
                "confirmed": true,
                "domainId": 5
              }
            }
            """, MediaType.APPLICATION_JSON));

    AuthServerLoginResponseDTO response = authServerApiClient.login(
        new AuthServerLoginRequestDTO("user@example.org", "secret"));

    server.verify();
    assertThat(response).isNotNull();
    assertThat(response.token()).isEqualTo("user-jwt-token");
    assertThat(response.user()).isNotNull();
    assertThat(response.user().id()).isEqualTo(101L);
    assertThat(response.user().email()).isEqualTo("user@example.org");
    assertThat(response.user().confirmed()).isTrue();
    assertThat(response.user().domainId()).isEqualTo(5L);
  }

  @Test
  void updateSelfUsesUserJwtToken() {
    server.expect(requestTo("https://auth.example.org/api/external/domains/55/users/me"))
        .andExpect(method(HttpMethod.PUT))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer user-jwt-token"))
        .andExpect(jsonPath("$.password").value("new-secret"))
        .andExpect(jsonPath("$.values[0].fieldId").value(13))
        .andExpect(jsonPath("$.values[0].stringValue").value("Иван"))
        .andRespond(withSuccess());

    authServerApiClient.updateSelf(
        "user-jwt-token",
        new AuthServerUserSelfUpdateRequestDTO(
            "new-secret",
            List.of(AuthServerProfileValueDTO.stringValue(13L, "Имя", "Иван"))));

    server.verify();
  }

  @Test
  void registerPropagatesServerMessage() {
    server.expect(requestTo("https://auth.example.org/api/external/domains/55/users"))
        .andExpect(method(HttpMethod.POST))
        .andRespond(withBadRequest().contentType(MediaType.APPLICATION_JSON).body("""
            {"message":"Missing or unknown profile fields"}
            """));

    assertThatThrownBy(() -> authServerApiClient.register(registerRequest()))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining("Missing or unknown profile fields");
  }

  @Test
  void registerConflictPropagatesServerMessage() {
    server.expect(requestTo("https://auth.example.org/api/external/domains/55/users"))
        .andExpect(method(HttpMethod.POST))
        .andRespond(withStatus(HttpStatus.CONFLICT)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"message\":\"User already registered\"}"));

    assertThatThrownBy(() -> authServerApiClient.register(registerRequest()))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining("User already registered");
  }

  @Test
  void registerFailsWhenJwtTokenIsMissing() {
    properties.setApiToken("   ");

    assertThatThrownBy(() -> authServerApiClient.register(registerRequest()))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining("Auth server is not configured");
  }

  @Test
  void login401ReturnsLocalizedMessage() {
    server.expect(requestTo("https://auth.example.org/api/external/domains/55/users/login"))
        .andExpect(method(HttpMethod.POST))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"message\":\"Invalid credentials\"}"));

    assertThatThrownBy(() -> authServerApiClient.login(new AuthServerLoginRequestDTO("user@example.org", "bad")))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining(
            "Пользователь с таким email  не зарегистрирован или email не подтвержден или email/пароль не совпадают");
  }

  private AuthServerRegisterRequestDTO registerRequest() {
    return new AuthServerRegisterRequestDTO(
        "user@example.org",
        "secret",
        List.of(
            AuthServerProfileValueDTO.stringValue(12L, "Фамилия", "Иванов"),
            AuthServerProfileValueDTO.stringValue(13L, "Имя", "Иван"),
            AuthServerProfileValueDTO.stringValue(14L, "Отчество.", "Иванович"),
            AuthServerProfileValueDTO.stringValue(15L, "Паспорт", "AB123456"),
            AuthServerProfileValueDTO.stringValue(16L, "IDNP", "1234567890123"),
            AuthServerProfileValueDTO.dateValue(17L, "Дата рождения", LocalDate.of(1990, 1, 15)),
            AuthServerProfileValueDTO.numericValue(21L, "Телефон", "37360000000")
        ));
  }
}
