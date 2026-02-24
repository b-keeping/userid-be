package com.userid.dal.repo;

import com.userid.dal.entity.OwnerEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerRepository extends JpaRepository<OwnerEntity, Long> {
  Optional<OwnerEntity> findByEmail(String email);

  Optional<OwnerEntity> findFirstByRole(com.userid.dal.entity.OwnerRoleEnum role);

  boolean existsByRole(com.userid.dal.entity.OwnerRoleEnum role);

  boolean existsByEmail(String email);
}
