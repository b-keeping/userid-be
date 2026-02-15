package com.userid.api.client;

public final class UseridApiEndpoints {
  public static final String EXTERNAL_DOMAIN_USERS_BASE = "/api/external/domains/{domainId}/users";
  public static final String EXTERNAL_DOMAIN_USERS_WILDCARD_BASE = "/api/external/domains/*/users";

  public static final String LOGIN = "/login";
  public static final String CONFIRM = "/confirm";
  public static final String FORGOT_PASSWORD = "/forgot-password";
  public static final String RESET_PASSWORD = "/reset-password";
  public static final String RESEND_VERIFICATION = "/resend-verification";
  public static final String ME = "/me";
  public static final String ALL_SUBPATHS = "/**";

  private static final String DOMAIN_ID_PLACEHOLDER = "{domainId}";

  private UseridApiEndpoints() {
  }

  public static String externalDomainUsers(Long domainId) {
    return EXTERNAL_DOMAIN_USERS_BASE.replace(DOMAIN_ID_PLACEHOLDER, String.valueOf(domainId));
  }

  public static String externalDomainUsersConfirm(Long domainId) {
    return externalDomainUsers(domainId) + CONFIRM;
  }

  public static String externalDomainUsersLogin(Long domainId) {
    return externalDomainUsers(domainId) + LOGIN;
  }

  public static String externalDomainUsersMe(Long domainId) {
    return externalDomainUsers(domainId) + ME;
  }
}
