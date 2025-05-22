package storties.auth.stortiesauthservice.persistence.repository;

import org.springframework.data.repository.CrudRepository;
import storties.auth.stortiesauthservice.persistence.User;

import java.util.Optional;

public interface UserJpaRepository extends CrudRepository<User, Long> {
    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);
}
