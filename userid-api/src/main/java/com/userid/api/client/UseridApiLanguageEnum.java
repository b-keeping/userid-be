package com.userid.api.client;

import java.util.Locale;

public enum UseridApiLanguageEnum {
  RU,
  EN;

  public Locale toLocale() {
    return switch (this) {
      case RU -> Locale.forLanguageTag("ru");
      case EN -> Locale.ENGLISH;
    };
  }
}
