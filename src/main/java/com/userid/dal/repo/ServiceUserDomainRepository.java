package com.userid.dal.repo;

import com.userid.dal.entity.ServiceUserDomain;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ServiceUserDomainRepository extends JpaRepository<ServiceUserDomain, Long> {
  List<ServiceUserDomain> findByServiceUserId(Long serviceUserId);

  boolean existsByServiceUserIdAndDomainId(Long serviceUserId, Long domainId);

  List<ServiceUserDomain> findByDomainId(Long domainId);

  void deleteByServiceUserId(Long serviceUserId);

  void deleteByServiceUserIdAndDomainId(Long serviceUserId, Long domainId);

  void deleteByDomainId(Long domainId);
}
