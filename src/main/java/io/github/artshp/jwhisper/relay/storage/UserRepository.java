package io.github.artshp.jwhisper.relay.storage;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for {@code JW_USERS} database table with users.
 */
@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    /**
     * Find user by username.
     * @param username username
     * @return user if found, otherwise {@link Optional#empty()}
     */
    Optional<UserEntity> findByUsername(String username);

    /**
     * Does user with given username exist?
     * @param username username
     * @return {@code true} if user exists, otherwise {@code false}
     */
    boolean existsByUsername(String username);
}
