package com.userid.dal.repo;

import com.userid.dal.entity.OtpOwner;
import com.userid.dal.entity.OtpType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpOwnerRepository extends JpaRepository<OtpOwner, Long> {
  Optional<OtpOwner> findByCodeAndType(String code, OtpType type);

  boolean existsByCodeAndType(String code, OtpType type);

  void deleteByOwnerIdAndType(Long ownerId, OtpType type);
}
