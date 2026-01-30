package com.userid.api.domain;

import com.userid.dal.entity.FieldType;

public record ProfileFieldResponse(
    Long id,
    String key,
    String label,
    FieldType type,
    boolean mandatory,
    Integer sortOrder
) {}
