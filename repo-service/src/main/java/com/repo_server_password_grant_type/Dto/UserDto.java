package com.repo_server_password_grant_type.Dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class UserDto {
    private String firstname;

    private String password;

    private String email;

    private String lastname;

    private String contact_no;
}
