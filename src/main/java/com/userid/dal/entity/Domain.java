package com.userid.dal.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashSet;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "domains")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Domain {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 255)
  private String name;

  @Column(name = "postal_status", length = 32)
  private String postalStatus;

  @Column(name = "postal_error", length = 1024)
  private String postalError;

  @Column(name = "postal_domain_jsonb", columnDefinition = "jsonb")
  @JdbcTypeCode(SqlTypes.JSON)
  private JsonNode postalDomainJsonb;

  @Column(name = "postal_dns_records_jsonb", columnDefinition = "jsonb")
  @JdbcTypeCode(SqlTypes.JSON)
  private JsonNode postalDnsRecordsJsonb;

  @Column(name = "postal_dns_check_jsonb", columnDefinition = "jsonb")
  @JdbcTypeCode(SqlTypes.JSON)
  private JsonNode postalDnsCheckJsonb;

  @Builder.Default
  @OneToMany(mappedBy = "domain", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<ProfileField> profileFields = new HashSet<>();

  @Builder.Default
  @OneToMany(mappedBy = "domain", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<User> users = new HashSet<>();
}
