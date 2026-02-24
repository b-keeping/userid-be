package com.userid.api.domain;

import com.userid.dal.entity.FieldTypeEnum;

public record ProfileFieldResponseDTO(
    Long id,
    String name,
    FieldTypeEnum type,
    boolean mandatory,
    Integer sortOrder
) {}
