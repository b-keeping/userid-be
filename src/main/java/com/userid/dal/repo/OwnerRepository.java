package com.userid.dal.repo;

import com.userid.dal.entity.Owner;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerRepository extends JpaRepository<Owner, Long> {
  Optional<Owner> findByEmail(String email);

  Optional<Owner> findByVerificationToken(String verificationToken);

  Optional<Owner> findByResetToken(String resetToken);

  Optional<Owner> findFirstByRole(com.userid.dal.entity.OwnerRole role);

  boolean existsByRole(com.userid.dal.entity.OwnerRole role);

  boolean existsByEmail(String email);
}
