package com.userid.dal.repo;

import com.userid.dal.entity.ServiceUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ServiceUserRepository extends JpaRepository<ServiceUser, Long> {
  Optional<ServiceUser> findByUsername(String username);

  boolean existsByRole(com.userid.dal.entity.ServiceUserRole role);

  boolean existsByUsername(String username);
}
