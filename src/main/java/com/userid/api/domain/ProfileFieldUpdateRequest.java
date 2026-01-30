package com.userid.api.domain;

import com.userid.dal.entity.FieldType;

public record ProfileFieldUpdateRequest(
    String key,
    String label,
    FieldType type,
    Boolean mandatory,
    Integer sortOrder
) {}
