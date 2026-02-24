package com.userid.service;

import com.userid.dal.entity.FieldTypeEnum;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;

public record UserSearchFilterDTO(
    Long fieldId,
    FieldTypeEnum type,
    String stringValue,
    Boolean booleanValue,
    Long integerValue,
    BigDecimal decimalValue,
    LocalDate dateValue,
    LocalTime timeValue,
    OffsetDateTime timestampValue
) {}
