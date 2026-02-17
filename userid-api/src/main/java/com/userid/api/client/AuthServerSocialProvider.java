package com.userid.api.client;

import java.util.Arrays;

public enum AuthServerSocialProvider {
  GOOGLE("google"),
  YANDEX("yandex"),
  VK("vk");

  private final String pathValue;

  AuthServerSocialProvider(String pathValue) {
    this.pathValue = pathValue;
  }

  public String pathValue() {
    return pathValue;
  }

  public static AuthServerSocialProvider fromPath(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("Social provider is required");
    }
    String normalized = value.trim();
    return Arrays.stream(values())
        .filter(provider -> provider.pathValue.equalsIgnoreCase(normalized)
            || provider.name().equalsIgnoreCase(normalized))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unsupported social provider: " + value));
  }
}
