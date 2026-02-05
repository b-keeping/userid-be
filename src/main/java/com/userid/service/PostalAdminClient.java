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

  public PostalAdminResponse checkDomain(String organization, String server, String domain) {
    try {
      Map<String, String> payload = new HashMap<>();
      payload.put("organization", organization);
      payload.put("server", server);
      payload.put("domain", domain);

      String body = objectMapper.writeValueAsString(payload);
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(baseUrl + "/domain/check"))
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

      JsonNode root = objectMapper.readTree(response.body());
      boolean ok = root.path("ok").asBoolean(false);
      JsonNode domainNode = root.path("domain").isMissingNode() ? null : root.path("domain");
      JsonNode dnsRecords = root.path("dns_records").isMissingNode() ? null : root.path("dns_records");
      JsonNode dnsCheck = root.path("dns_check").isMissingNode() ? null : root.path("dns_check");
      String error = root.path("error").asText(null);
      return new PostalAdminResponse(ok, domainNode, dnsRecords, dnsCheck, error);
    } catch (IOException | InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Postal admin request failed: " + ex.getMessage(), ex);
    }
  }

  public record PostalAdminResponse(
      boolean ok,
      JsonNode domain,
      JsonNode dnsRecords,
      JsonNode dnsCheck,
      String error
  ) {}
}
