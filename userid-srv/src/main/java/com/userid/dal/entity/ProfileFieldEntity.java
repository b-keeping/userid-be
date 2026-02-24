package com.userid.dal.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
    name = "profile_fields",
    uniqueConstraints = {
      @UniqueConstraint(
          name = "uk_profile_fields_domain_name",
          columnNames = {"domain_id", "name"}
      )
    },
    indexes = {
      @Index(name = "idx_profile_fields_domain", columnList = "domain_id"),
      @Index(name = "idx_profile_fields_domain_name", columnList = "domain_id,name")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProfileFieldEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "domain_id", nullable = false)
  private DomainEntity domain;

  @Column(nullable = false, length = 255)
  private String name;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 16)
  private FieldTypeEnum type;

  @Column(nullable = false)
  private boolean mandatory;

  @Column(name = "sort_order")
  private Integer sortOrder;
}
