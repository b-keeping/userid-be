package com.userid.util;

import java.util.Locale;
import org.springframework.util.StringUtils;

public final class EmailNormalizer {
  private EmailNormalizer() {
  }

  public static String normalizeNullable(String email) {
    if (!StringUtils.hasText(email)) {
      return null;
    }
    return email.trim().toLowerCase(Locale.ROOT);
  }
}
