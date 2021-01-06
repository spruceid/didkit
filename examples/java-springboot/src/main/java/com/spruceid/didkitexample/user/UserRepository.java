package com.spruceid.didkitexample.user;

import com.spruceid.didkitexample.entity.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
