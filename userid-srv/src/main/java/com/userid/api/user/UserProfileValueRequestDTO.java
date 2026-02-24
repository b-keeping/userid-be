package com.userid.api.user;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;

public record UserProfileValueRequestDTO(
    Long fieldId,
    String name,
    String stringValue,
    String numericValue,
    Boolean booleanValue,
    Long integerValue,
    BigDecimal decimalValue,
    LocalDate dateValue,
    LocalTime timeValue,
    OffsetDateTime timestampValue
) {}
