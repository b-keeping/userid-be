package com.userid.dal.repo;

import com.userid.dal.entity.UserProfileValue;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface UserProfileValueRepository extends JpaRepository<UserProfileValue, Long> {
  List<UserProfileValue> findByUserId(Long userId);

  @Transactional
  void deleteByUserId(Long userId);

  @Transactional
  void deleteByFieldId(Long fieldId);

  long countByFieldId(Long fieldId);
}
