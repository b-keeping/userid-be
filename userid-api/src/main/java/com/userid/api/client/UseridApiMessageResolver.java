package com.userid.api.client;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

public class UseridApiMessageResolver {
  private static final String BUNDLE_BASE_NAME = "userid-api-messages";

  private final AuthServerApiProperties properties;

  public UseridApiMessageResolver(AuthServerApiProperties properties) {
    this.properties = properties;
  }

  public String loginUnauthorizedMessage() {
    return getMessage(
        "auth.login.unauthorized",
        "User with this email is not registered, or email is not confirmed, or email/password do not match.");
  }

  public String registerConfirmationSentMessage() {
    return getMessage(
        "auth.register.confirmation_sent",
        "A confirmation email with instructions has been sent to your email address.");
  }

  private String getMessage(String key, String fallback) {
    UseridApiLanguage language = properties.getLanguage();
    Locale locale = language == null ? Locale.ENGLISH : language.toLocale();
    try {
      ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE_BASE_NAME, locale);
      if (bundle.containsKey(key)) {
        return bundle.getString(key);
      }
    } catch (MissingResourceException ignored) {
      // Ignore and use fallback.
    }
    return fallback;
  }
}
