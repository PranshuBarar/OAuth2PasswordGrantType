package com.repo_server_password_grant_type.services;

import com.repo_server_password_grant_type.entities.UserEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import java.util.Collection;

@Setter
@Getter
public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(UserEntity userEntity, Collection<? extends GrantedAuthority> authorities) {
        this.userEntity = userEntity;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userEntity.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
