# userid-be

Auth service for domain-based user registration with dynamic profile fields.

## ERD (PostgreSQL)

```mermaid
erDiagram
  domains {
    bigint id PK
    varchar code "unique"
    varchar name
  }

  profile_fields {
    bigint id PK
    bigint domain_id FK
    varchar field_key
    varchar label
    varchar type
    boolean mandatory
    int sort_order
  }

  users {
    bigint id PK
    bigint domain_id FK
    varchar login
    varchar email
    timestamptz created_at
    jsonb profile_jsonb
  }

  service_users {
    bigint id PK
    varchar username "unique"
    varchar password_hash
    varchar role
    timestamptz created_at
  }

  service_user_domains {
    bigint id PK
    bigint service_user_id FK
    bigint domain_id FK
    timestamptz created_at
  }

  user_profile_values {
    bigint id PK
    bigint user_id FK
    bigint field_id FK
    varchar value_string
    boolean value_boolean
    bigint value_integer
    numeric value_decimal
    date value_date
    time value_time
    timestamptz value_timestamp
  }

  domains ||--o{ profile_fields : has
  domains ||--o{ users : has
  users ||--o{ user_profile_values : has
  profile_fields ||--o{ user_profile_values : uses
  service_users ||--o{ service_user_domains : links
  domains ||--o{ service_user_domains : links
```

### Indexes (core for fast fetch)
- `profile_fields (domain_id, field_key)` unique for schema lookup by domain.
- `users (domain_id, login)` unique for user lookup per domain.
- `user_profile_values (user_id)` for fast fetch of user profile.
- `user_profile_values (field_id, value_*)` per-type composite indexes for fast filtering.

## API

### Domains
- `POST /api/domains`
- `GET /api/domains`
- `PUT /api/domains/{domainId}`
- `DELETE /api/domains/{domainId}`

### Profile fields per domain
- `POST /api/domains/{domainId}/profile-fields`
- `GET /api/domains/{domainId}/profile-fields`
- `PUT /api/domains/{domainId}/profile-fields/{fieldId}`
- `DELETE /api/domains/{domainId}/profile-fields/{fieldId}`

### Users
- `POST /api/domains/{domainId}/users` - register user with profile values
- `GET /api/domains/{domainId}/users/{userId}` - fetch user with profile values
- `POST /api/domains/{domainId}/users/search` - filter users by profile values
- `PUT /api/domains/{domainId}/users/{userId}`
- `DELETE /api/domains/{domainId}/users/{userId}`

### Service users (access control)
- `POST /api/auth/login` - login service user (returns JWT)
- `POST /api/service-users` - create service user (admin only)
- `GET /api/service-users` - list service users (admin only)
- `GET /api/service-users/{userId}` - get service user (admin or self)
- `POST /api/service-users/{userId}/domains` - link domain to USER (admin only)
- `PUT /api/service-users/{userId}`
- `DELETE /api/service-users/{userId}`
- `DELETE /api/service-users/{userId}/domains/{domainId}`

## Notes
- Each profile value row stores a single typed value, enforced in service validation.
- Search is implemented as `EXISTS` subqueries per filter to use `field_id + value_*` indexes.
- `users.profile_jsonb` stores a denormalized snapshot of profile values and is used for user fetch responses.
- Requests must include `Authorization: Bearer <JWT>` for access checks (admin vs domain-linked user).
- Default auth service port: `8282` (override with `AUTH_PORT`).
