package com.res_server_password_grant_type.controller;

import com.repo_server_password_grant_type.Dto.UserDto;
import com.res_server_password_grant_type.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
public class HomeController {


	private final UserService userService;

	@GetMapping("/")
	public String home(Authentication authentication) {
		return "Hello From Resource Server " + authentication.getName();
	}

	@PutMapping("/signup")
	public ResponseEntity<?> signup(@RequestBody UserDto userDto){
		String response = userService.signup(userDto);
		return new ResponseEntity<>(response, HttpStatus.OK);
	}
}