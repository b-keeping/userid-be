package com.userid.api.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDate;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthServerProfileValueDTO(
    Long fieldId,
    String name,
    String stringValue,
    String numericValue,
    LocalDate dateValue
) {
  public static AuthServerProfileValueDTO stringValue(Long fieldId, String name, String value) {
    return new AuthServerProfileValueDTO(fieldId, name, value, null, null);
  }

  public static AuthServerProfileValueDTO numericValue(Long fieldId, String name, String value) {
    return new AuthServerProfileValueDTO(fieldId, name, null, value, null);
  }

  public static AuthServerProfileValueDTO dateValue(Long fieldId, String name, LocalDate value) {
    return new AuthServerProfileValueDTO(fieldId, name, null, null, value);
  }
}
