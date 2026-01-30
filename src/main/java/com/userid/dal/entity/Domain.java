package com.userid.dal.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.HashSet;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
    name = "domains",
    uniqueConstraints = {
      @UniqueConstraint(name = "uk_domains_code", columnNames = {"code"})
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Domain {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 64)
  private String code;

  @Column(nullable = false, length = 255)
  private String name;

  @Builder.Default
  @OneToMany(mappedBy = "domain", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<ProfileField> profileFields = new HashSet<>();

  @Builder.Default
  @OneToMany(mappedBy = "domain", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<User> users = new HashSet<>();
}
