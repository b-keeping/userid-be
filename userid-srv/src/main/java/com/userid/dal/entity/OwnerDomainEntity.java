package com.userid.dal.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
    name = "owner_domain",
    uniqueConstraints = {
      @UniqueConstraint(name = "uk_owner_domains_owner_domain", columnNames = {"owner_id", "domain_id"}),
      @UniqueConstraint(name = "uk_owner_domains_domain", columnNames = {"domain_id"})
    },
    indexes = {
      @Index(name = "idx_owner_domains_owner", columnList = "owner_id"),
      @Index(name = "idx_owner_domains_domain", columnList = "domain_id")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OwnerDomainEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "owner_id", nullable = false)
  private OwnerEntity owner;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "domain_id", nullable = false)
  private DomainEntity domain;

  @Column(name = "created_at", nullable = false)
  private OffsetDateTime createdAt;
}
