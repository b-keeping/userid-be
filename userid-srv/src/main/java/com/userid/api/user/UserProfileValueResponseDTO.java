package com.userid.api.user;

import com.userid.dal.entity.FieldTypeEnum;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;

public record UserProfileValueResponseDTO(
    Long fieldId,
    String name,
    FieldTypeEnum type,
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
