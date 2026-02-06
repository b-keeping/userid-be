package com.userid.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class DnsAdminClient {
  private final ObjectMapper objectMapper;
  private final HttpClient httpClient;
  private final String baseUrl;
  private final String token;
  private final String tokenHeader;
  private final Duration timeout;

  public DnsAdminClient(
      ObjectMapper objectMapper,
      @Value("${auth.dns-admin.base-url}") String baseUrl,
      @Value("${auth.dns-admin.token}") String token,
      @Value("${auth.dns-admin.token-header:X-Admin-Token}") String tokenHeader,
      @Value("${auth.dns-admin.timeout-seconds:15}") long timeoutSeconds
  ) {
    this.objectMapper = objectMapper;
    this.baseUrl = baseUrl;
    this.token = token;
    this.tokenHeader = tokenHeader;
    this.timeout = Duration.ofSeconds(timeoutSeconds);
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(this.timeout)
        .build();
  }

  public ProvisionResponse provisionDomain(
      String organization,
      String templateServer,
      String server,
      String domain
  ) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("template_server", templateServer);
    payload.put("server", server);
    payload.put("domain", domain);

    JsonNode root = postJson("/provision", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode records = root.path("records").isMissingNode() ? null : root.path("records");
    String error = root.path("error").asText(null);
    return new ProvisionResponse(ok, records, error);
  }

  public VerifyCheckResponse verifyCheck(String organization, String server, String domain) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("server", server);
    payload.put("domain", domain);

    JsonNode root = postJson("/domain/verify-check", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode record = root.path("record").isMissingNode() ? null : root.path("record");
    String error = root.path("error").asText(null);
    return new VerifyCheckResponse(ok, record, error);
  }

  public DnsCheckResponse dnsCheck(String organization, String server, String domain) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("server", server);
    payload.put("domain", domain);

    JsonNode root = postJson("/domain/dns-check", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode records = root.path("records").isMissingNode() ? null : root.path("records");
    String error = root.path("error").asText(null);
    return new DnsCheckResponse(ok, records, error);
  }

  private JsonNode postJson(String path, Object payload) {
    try {
      String body = objectMapper.writeValueAsString(payload);
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(baseUrl + path))
          .timeout(timeout)
          .header("Content-Type", "application/json")
          .header(tokenHeader, token)
          .POST(HttpRequest.BodyPublishers.ofString(body))
          .build();

      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() >= 400) {
        throw new ResponseStatusException(
            HttpStatus.BAD_GATEWAY,
            "Admin error: " + response.statusCode() + " " + response.body()
        );
      }
      return objectMapper.readTree(response.body());
    } catch (IOException | InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Admin request failed: " + ex.getMessage(), ex);
    }
  }

  public record ProvisionResponse(
      boolean ok,
      JsonNode records,
      String error
  ) {}

  public record VerifyCheckResponse(
      boolean ok,
      JsonNode record,
      String error
  ) {}

  public record DnsCheckResponse(
      boolean ok,
      JsonNode records,
      String error
  ) {}
}
