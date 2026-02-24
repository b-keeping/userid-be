package com.userid.dal.repo;

import com.userid.dal.entity.DomainEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DomainRepository extends JpaRepository<DomainEntity, Long> {
}
