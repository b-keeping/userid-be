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
public class PostalAdminClient {
  private final ObjectMapper objectMapper;
  private final HttpClient httpClient;
  private final String baseUrl;
  private final String token;
  private final Duration timeout;

  public PostalAdminClient(
      ObjectMapper objectMapper,
      @Value("${auth.postal-admin.base-url}") String baseUrl,
      @Value("${auth.postal-admin.token}") String token,
      @Value("${auth.postal-admin.timeout-seconds:15}") long timeoutSeconds
  ) {
    this.objectMapper = objectMapper;
    this.baseUrl = baseUrl;
    this.token = token;
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
    JsonNode values = root.path("values").isMissingNode() ? null : root.path("values");
    String error = root.path("error").asText(null);
    return new ProvisionResponse(ok, values, error);
  }

  public VerifyCheckResponse verifyCheck(String organization, String server, String domain) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("server", server);
    payload.put("domain", domain);

    JsonNode root = postJson("/domain/verify-check", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode verification = root.path("verification").isMissingNode() ? null : root.path("verification");
    String error = root.path("error").asText(null);
    return new VerifyCheckResponse(ok, verification, error);
  }

  public DnsCheckResponse dnsCheck(String organization, String server, String domain) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("server", server);
    payload.put("domain", domain);

    JsonNode root = postJson("/domain/dns-check", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode spf = root.path("spf").isMissingNode() ? null : root.path("spf");
    JsonNode dkim = root.path("dkim").isMissingNode() ? null : root.path("dkim");
    JsonNode returnPath = root.path("return_path").isMissingNode() ? null : root.path("return_path");
    JsonNode mx = root.path("mx").isMissingNode() ? null : root.path("mx");
    String error = root.path("error").asText(null);
    return new DnsCheckResponse(ok, spf, dkim, returnPath, mx, error);
  }

  private JsonNode postJson(String path, Object payload) {
    try {
      String body = objectMapper.writeValueAsString(payload);
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(baseUrl + path))
          .timeout(timeout)
          .header("Content-Type", "application/json")
          .header("X-Postal-Admin-Token", token)
          .POST(HttpRequest.BodyPublishers.ofString(body))
          .build();

      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() >= 400) {
        throw new ResponseStatusException(
            HttpStatus.BAD_GATEWAY,
            "Postal admin error: " + response.statusCode() + " " + response.body()
        );
      }
      return objectMapper.readTree(response.body());
    } catch (IOException | InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Postal admin request failed: " + ex.getMessage(), ex);
    }
  }

  public record ProvisionResponse(
      boolean ok,
      JsonNode values,
      String error
  ) {}

  public record VerifyCheckResponse(
      boolean ok,
      JsonNode verification,
      String error
  ) {}

  public record DnsCheckResponse(
      boolean ok,
      JsonNode spf,
      JsonNode dkim,
      JsonNode returnPath,
      JsonNode mx,
      String error
  ) {}
}
