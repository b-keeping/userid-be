package com.userid.api.client;

import java.util.Locale;

public final class EmailNormalizer {
  private EmailNormalizer() {
  }

  public static String normalizeNullable(String email) {
    if (email == null) {
      return null;
    }
    String trimmed = email.trim();
    if (trimmed.isEmpty()) {
      return null;
    }
    return trimmed.toLowerCase(Locale.ROOT);
  }
}
