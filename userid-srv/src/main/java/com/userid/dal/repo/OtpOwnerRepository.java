package com.userid.dal.repo;

import com.userid.dal.entity.OtpOwnerEntity;
import com.userid.dal.entity.OtpTypeEnum;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface OtpOwnerRepository extends JpaRepository<OtpOwnerEntity, Long> {
  Optional<OtpOwnerEntity> findByCodeAndType(String code, OtpTypeEnum type);

  Optional<OtpOwnerEntity> findTopByOwnerIdAndTypeOrderByCreatedAtDesc(Long ownerId, OtpTypeEnum type);

  boolean existsByCodeAndType(String code, OtpTypeEnum type);

  @Transactional
  void deleteByOwnerId(Long ownerId);

  @Transactional
  void deleteByOwnerIdAndType(Long ownerId, OtpTypeEnum type);
}
