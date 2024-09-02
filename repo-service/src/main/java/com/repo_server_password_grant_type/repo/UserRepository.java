package com.repo_server_password_grant_type.repo;




import com.repo_server_password_grant_type.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, UUID> {

    UserEntity findByEmail(String email);

    UserEntity findByUserId(UUID userId);
}
