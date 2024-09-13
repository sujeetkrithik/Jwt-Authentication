package com.security.Jwt.Authentication.Security.repository;

import com.security.Jwt.Authentication.Security.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users, Long>{

    Optional<Users> findByUsername(String username);
}


