package com.res_server_password_grant_type.config;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Order(2)
@AllArgsConstructor
public class ResSecurityConfig {

	@Autowired
	public final JwtDecoder jwtDecoder;
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				.csrf(req -> req.ignoringRequestMatchers("/signup"))
				.authorizeHttpRequests(req -> req.requestMatchers("/signup")
						.permitAll()
						.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2
						.jwt(jwt -> jwt.decoder(jwtDecoder)))
				.formLogin(Customizer.withDefaults())
				.build();


	}
}