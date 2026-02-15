package com.userid.api.client;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
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
    authServerApiClient =
        new AuthServerApiClient(restTemplate, properties, new ObjectMapper().findAndRegisterModules());
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
  void registerFailsWhenJwtTokenIsMissing() {
    properties.setApiToken("   ");

    assertThatThrownBy(() -> authServerApiClient.register(registerRequest()))
        .isInstanceOf(ResponseStatusException.class)
        .hasMessageContaining("Auth server is not configured");
  }

  private AuthServerRegisterRequest registerRequest() {
    return new AuthServerRegisterRequest(
        "user@example.org",
        "secret",
        List.of(
            AuthServerProfileValue.stringValue(12L, "Фамилия", "Иванов"),
            AuthServerProfileValue.stringValue(13L, "Имя", "Иван"),
            AuthServerProfileValue.stringValue(14L, "Отчество.", "Иванович"),
            AuthServerProfileValue.stringValue(15L, "Паспорт", "AB123456"),
            AuthServerProfileValue.stringValue(16L, "IDNP", "1234567890123"),
            AuthServerProfileValue.dateValue(17L, "Дата рождения", LocalDate.of(1990, 1, 15)),
            AuthServerProfileValue.numericValue(21L, "Телефон", "37360000000")
        ));
  }
}
