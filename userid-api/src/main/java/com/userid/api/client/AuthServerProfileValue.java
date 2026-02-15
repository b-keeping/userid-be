package com.userid.api.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDate;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthServerProfileValue(
    Long fieldId,
    String name,
    String stringValue,
    String numericValue,
    LocalDate dateValue
) {
  public static AuthServerProfileValue stringValue(Long fieldId, String name, String value) {
    return new AuthServerProfileValue(fieldId, name, value, null, null);
  }

  public static AuthServerProfileValue numericValue(Long fieldId, String name, String value) {
    return new AuthServerProfileValue(fieldId, name, null, value, null);
  }

  public static AuthServerProfileValue dateValue(Long fieldId, String name, LocalDate value) {
    return new AuthServerProfileValue(fieldId, name, null, null, value);
  }
}
