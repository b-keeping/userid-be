package com.userid.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class PostalProvisionService {
  private static final String RAILS_SCRIPT = """
      set -e
      cd /opt/postal/app
      bundle exec rails runner '
      require "securerandom"
      require "json"

      org_name    = ENV.fetch("ORG_NAME")
      server_name = ENV.fetch("SERVER_NAME")
      domain_name = ENV.fetch("DOMAIN_NAME")

      org = Organization.find_by(name: org_name)
      raise "Organization not found by name=#{org_name}" unless org

      server = Server.find_or_create_by!(organization_id: org.id, name: server_name) do |s|
        s.mode = "Live" if s.respond_to?(:mode=)
      end

      domain = Domain.where(name: domain_name).first

      if domain.nil?
        domain = Domain.new
        domain.name = domain_name if domain.respond_to?(:name=)
        domain.server_id = server.id if domain.respond_to?(:server_id=)
        domain.organization_id = org.id if domain.respond_to?(:organization_id=)
        domain.save!
      else
        if domain.respond_to?(:server_id) && domain.respond_to?(:server_id=) && domain.server_id.nil?
          domain.server_id = server.id
          domain.save!
        end
      end

      def ensure_cred(server, type, name)
        c = Credential.where(server_id: server.id, type: type, name: name).first
        return c if c
        Credential.create!(
          server_id: server.id,
          type: type,
          name: name,
          key: SecureRandom.hex(32),
          hold: false
        )
      end

      api  = ensure_cred(server, "API",  "api-auto")
      smtp = ensure_cred(server, "SMTP", "smtp-auto")

      puts({
        organization: { id: org.id, name: org.name },
        server: { id: server.id, name: server.name, token: server.token },
        domain: { id: domain.id, name: domain.name },
        credentials: {
          api:  { id: api.id,  key: api.key },
          smtp: { id: smtp.id, key: smtp.key }
        }
      }.to_json)
      '
      """;

  private final ObjectMapper objectMapper;
  private final String postalContainer;
  private final Duration timeout;

  public PostalProvisionService(
      ObjectMapper objectMapper,
      @Value("${auth.postal.container:postal_web}") String postalContainer,
      @Value("${auth.postal.timeout-seconds:60}") long timeoutSeconds
  ) {
    this.objectMapper = objectMapper;
    this.postalContainer = postalContainer;
    this.timeout = Duration.ofSeconds(timeoutSeconds);
  }

  public PostalProvisionResult provision(String organizationName, String serverName, String domainName) {
    if (organizationName == null || organizationName.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Organization name is required");
    }
    if (serverName == null || serverName.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Server name is required");
    }
    if (domainName == null || domainName.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Domain name is required");
    }

    List<String> command = new ArrayList<>();
    command.add("docker");
    command.add("exec");
    command.add("-i");
    command.add("-e");
    command.add("ORG_NAME=" + organizationName);
    command.add("-e");
    command.add("SERVER_NAME=" + serverName);
    command.add("-e");
    command.add("DOMAIN_NAME=" + domainName);
    command.add(postalContainer);
    command.add("sh");
    command.add("-lc");
    command.add(RAILS_SCRIPT);

    ProcessBuilder builder = new ProcessBuilder(command);
    builder.redirectErrorStream(true);

    try {
      Process process = builder.start();
      boolean finished = process.waitFor(timeout.toSeconds(), TimeUnit.SECONDS);
      String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();

      if (!finished) {
        process.destroyForcibly();
        throw new ResponseStatusException(HttpStatus.GATEWAY_TIMEOUT, "Postal command timed out");
      }

      if (process.exitValue() != 0) {
        throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Postal command failed: " + output);
      }

      String json = extractJson(output);
      return objectMapper.readValue(json, PostalProvisionResult.class);
    } catch (IOException | InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Postal command error: " + ex.getMessage(), ex);
    }
  }

  private String extractJson(String output) {
    if (output == null || output.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Postal returned empty output");
    }
    int index = output.lastIndexOf('{');
    if (index < 0) {
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Postal output does not contain JSON: " + output);
    }
    return output.substring(index).trim();
  }

  public record PostalProvisionResult(
      PostalOrganization organization,
      PostalServer server,
      PostalDomain domain,
      PostalCredentials credentials
  ) {}

  public record PostalOrganization(Long id, String name) {}

  public record PostalServer(Long id, String name, String token) {}

  public record PostalDomain(Long id, String name) {}

  public record PostalCredentials(PostalCredential api, PostalCredential smtp) {}

  public record PostalCredential(Long id, String key) {}
}
