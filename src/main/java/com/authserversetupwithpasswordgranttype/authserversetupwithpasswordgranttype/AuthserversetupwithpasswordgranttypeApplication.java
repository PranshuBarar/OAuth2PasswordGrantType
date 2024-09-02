package com.authserversetupwithpasswordgranttype.authserversetupwithpasswordgranttype;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories("com.repo_server_password_grant_type.repo")
@EntityScan("com.repo_server_password_grant_type.entities")
@SpringBootApplication(scanBasePackages = {"com.auth_server_password_grant_type","com.res_server_password_grant_type","com.repo_server_password_grant_type.services"})
public class AuthserversetupwithpasswordgranttypeApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthserversetupwithpasswordgranttypeApplication.class, args);
	}

}
