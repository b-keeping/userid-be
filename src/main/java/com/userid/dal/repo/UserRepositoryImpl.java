package com.userid.dal.repo;

import com.userid.dal.entity.ProfileField;
import com.userid.dal.entity.User;
import com.userid.dal.entity.UserProfileValue;
import com.userid.service.UserSearchFilter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Fetch;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepositoryImpl implements UserRepositoryCustom {
  @PersistenceContext
  private EntityManager entityManager;

  @Override
  public List<User> searchByDomainAndFilters(Long domainId, List<UserSearchFilter> filters) {
    CriteriaBuilder cb = entityManager.getCriteriaBuilder();
    CriteriaQuery<User> cq = cb.createQuery(User.class);
    Root<User> userRoot = cq.from(User.class);

    Fetch<User, UserProfileValue> valuesFetch = userRoot.fetch("values", JoinType.LEFT);
    valuesFetch.fetch("field", JoinType.LEFT);

    List<Predicate> predicates = new ArrayList<>();
    predicates.add(cb.equal(userRoot.get("domain").get("id"), domainId));

    for (UserSearchFilter filter : filters) {
      Subquery<Long> subquery = cq.subquery(Long.class);
      Root<UserProfileValue> valueRoot = subquery.from(UserProfileValue.class);
      Join<UserProfileValue, ProfileField> fieldJoin = valueRoot.join("field", JoinType.INNER);

      List<Predicate> subPredicates = new ArrayList<>();
      subPredicates.add(cb.equal(valueRoot.get("user").get("id"), userRoot.get("id")));
      subPredicates.add(cb.equal(fieldJoin.get("id"), filter.fieldId()));

      switch (filter.type()) {
        case STRING -> subPredicates.add(cb.equal(valueRoot.get("valueString"), filter.stringValue()));
        case BOOLEAN -> subPredicates.add(cb.equal(valueRoot.get("valueBoolean"), filter.booleanValue()));
        case INTEGER -> subPredicates.add(cb.equal(valueRoot.get("valueInteger"), filter.integerValue()));
        case DECIMAL -> subPredicates.add(cb.equal(valueRoot.get("valueDecimal"), filter.decimalValue()));
        case DATE -> subPredicates.add(cb.equal(valueRoot.get("valueDate"), filter.dateValue()));
        case TIME -> subPredicates.add(cb.equal(valueRoot.get("valueTime"), filter.timeValue()));
        case TIMESTAMP -> subPredicates.add(cb.equal(valueRoot.get("valueTimestamp"), filter.timestampValue()));
      }

      subquery.select(valueRoot.get("id")).where(subPredicates.toArray(Predicate[]::new));
      predicates.add(cb.exists(subquery));
    }

    cq.select(userRoot).distinct(true).where(predicates.toArray(Predicate[]::new));

    TypedQuery<User> query = entityManager.createQuery(cq);
    return query.getResultList();
  }
}
