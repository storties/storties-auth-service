package storties.auth.stortiesauthservice.persistence.repository;

import org.springframework.data.repository.CrudRepository;
import storties.auth.stortiesauthservice.persistence.User;

public interface UserJpaRepository extends CrudRepository<User, Long> {
    boolean existsByEmail(String email);

    User findByEmail(String email);
}
