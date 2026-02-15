package com.userid.api.user;

import com.userid.dal.entity.FieldType;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;

public record UserProfileValueResponse(
    Long fieldId,
    String name,
    FieldType type,
    boolean mandatory,
    String stringValue,
    String numericValue,
    Boolean booleanValue,
    Long integerValue,
    BigDecimal decimalValue,
    LocalDate dateValue,
    LocalTime timeValue,
    OffsetDateTime timestampValue
) {}
