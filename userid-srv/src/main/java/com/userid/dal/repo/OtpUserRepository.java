package com.userid.dal.repo;

import com.userid.dal.entity.OtpType;
import com.userid.dal.entity.OtpUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface OtpUserRepository extends JpaRepository<OtpUser, Long> {
  Optional<OtpUser> findByCodeAndType(String code, OtpType type);

  boolean existsByCodeAndType(String code, OtpType type);

  @Transactional
  void deleteByUserId(Long userId);

  @Transactional
  void deleteByUserIdAndType(Long userId, OtpType type);
}
