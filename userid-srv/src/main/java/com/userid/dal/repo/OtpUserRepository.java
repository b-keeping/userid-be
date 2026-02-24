package com.userid.dal.repo;

import com.userid.dal.entity.OtpTypeEnum;
import com.userid.dal.entity.OtpUserEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface OtpUserRepository extends JpaRepository<OtpUserEntity, Long> {
  Optional<OtpUserEntity> findByCodeAndType(String code, OtpTypeEnum type);

  Optional<OtpUserEntity> findTopByUserIdAndTypeOrderByCreatedAtDesc(Long userId, OtpTypeEnum type);

  boolean existsByCodeAndType(String code, OtpTypeEnum type);

  @Transactional
  void deleteByUserId(Long userId);

  @Transactional
  void deleteByUserIdAndType(Long userId, OtpTypeEnum type);
}
