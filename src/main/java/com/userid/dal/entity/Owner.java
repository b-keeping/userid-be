package com.userid.dal.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

@Entity
@Table(
    name = "owners",
    uniqueConstraints = {
      @UniqueConstraint(name = "uk_owners_email", columnNames = {"email"})
    },
    indexes = {
      @Index(name = "idx_owners_role", columnList = "role")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Owner {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 255)
  private String email;

  @Column(name = "password_hash", length = 255)
  private String passwordHash;

  @Builder.Default
  @Column(name = "active", nullable = false)
  @ColumnDefault("false")
  private boolean active = false;

  @Column(name = "email_verified_at")
  private OffsetDateTime emailVerifiedAt;

  @Column(name = "verification_token", length = 80)
  private String verificationToken;

  @Column(name = "verification_expires_at")
  private OffsetDateTime verificationExpiresAt;

  @Column(name = "reset_token", length = 80)
  private String resetToken;

  @Column(name = "reset_expires_at")
  private OffsetDateTime resetExpiresAt;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 16)
  private OwnerRole role;

  @Column(name = "created_at", nullable = false)
  private OffsetDateTime createdAt;

  @Builder.Default
  @OneToMany(mappedBy = "owner", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<OwnerDomain> domains = new HashSet<>();
}
