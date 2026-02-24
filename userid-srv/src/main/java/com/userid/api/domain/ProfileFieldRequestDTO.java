package com.userid.api.domain;

import com.userid.dal.entity.FieldTypeEnum;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record ProfileFieldRequestDTO(
    @NotBlank String name,
    @NotNull FieldTypeEnum type,
    @NotNull Boolean mandatory,
    Integer sortOrder
) {}
