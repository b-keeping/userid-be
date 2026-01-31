package com.userid.dal.repo;

import com.userid.dal.entity.Owner;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerRepository extends JpaRepository<Owner, Long> {
  Optional<Owner> findByUsername(String username);

  boolean existsByRole(com.userid.dal.entity.OwnerRole role);

  boolean existsByUsername(String username);
}
