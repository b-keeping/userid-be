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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class PostalAdminClient {
  private static final Logger log = LoggerFactory.getLogger(PostalAdminClient.class);
  private final ObjectMapper objectMapper;
  private final HttpClient httpClient;
  private final String baseUrl;
  private final String token;
  private final String tokenHeader;
  private final Duration timeout;

  public PostalAdminClient(
      ObjectMapper objectMapper,
      @Value("${auth.postal-admin.base-url}") String baseUrl,
      @Value("${auth.postal-admin.token}") String token,
      @Value("${auth.postal-admin.token-header:X-Admin-Token}") String tokenHeader,
      @Value("${auth.postal-admin.timeout-seconds:15}") long timeoutSeconds
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

  public ProvisionResponseDTO provisionDomain(
      String organization,
      String templateServer,
      String server,
      String domain,
      String smtpName
  ) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("template_server", templateServer);
    payload.put("server", server);
    payload.put("domain", domain);
    payload.put("smtp_name", smtpName);

    JsonNode root = postJson("/provision", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode records = root.path("records").isMissingNode() ? null : root.path("records");
    JsonNode smtp = root.path("smtp");
    if (smtp.isMissingNode()) {
      JsonNode credentials = root.path("credentials");
      if (!credentials.isMissingNode()) {
        smtp = credentials.path("smtp");
      }
    }
    if (smtp.isMissingNode()) {
      smtp = null;
    }
    String error = root.path("error").asText(null);
    return new ProvisionResponseDTO(ok, records, smtp, error);
  }

  public VerifyCheckResponseDTO verifyCheck(String organization, String server, String domain) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("server", server);
    payload.put("domain", domain);

    JsonNode root = postJson("/domain/verify-check", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode record = root.path("record").isMissingNode() ? null : root.path("record");
    String error = root.path("error").asText(null);
    return new VerifyCheckResponseDTO(ok, record, error);
  }

  public DnsCheckResponseDTO dnsCheck(String organization, String server, String domain) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("organization", organization);
    payload.put("server", server);
    payload.put("domain", domain);

    JsonNode root = postJson("/domain/dns-check", payload);
    boolean ok = root.path("ok").asBoolean(false);
    JsonNode records = root.path("records").isMissingNode() ? null : root.path("records");
    String error = root.path("error").asText(null);
    return new DnsCheckResponseDTO(ok, records, error);
  }

  private JsonNode postJson(String path, Object payload) {
    try {
      String body = objectMapper.writeValueAsString(payload);
      log.info("Postal admin request {} payload={}", path, body);
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(baseUrl + path))
          .timeout(timeout)
          .header("Content-Type", "application/json")
          .header(tokenHeader, token)
          .POST(HttpRequest.BodyPublishers.ofString(body))
          .build();

      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      log.info("Postal admin response {} status={} body={}", path, response.statusCode(), response.body());
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

  public record ProvisionResponseDTO(
      boolean ok,
      JsonNode records,
      JsonNode smtp,
      String error
  ) {}

  public record VerifyCheckResponseDTO(
      boolean ok,
      JsonNode record,
      String error
  ) {}

  public record DnsCheckResponseDTO(
      boolean ok,
      JsonNode records,
      String error
  ) {}
}
