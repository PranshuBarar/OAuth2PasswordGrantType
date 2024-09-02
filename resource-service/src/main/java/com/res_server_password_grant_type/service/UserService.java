package com.res_server_password_grant_type.service;


import com.repo_server_password_grant_type.Dto.UserDto;
import com.repo_server_password_grant_type.entities.UserEntity;
import com.repo_server_password_grant_type.repo.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;

//    public String hello(){
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        UUID userId = UUID.fromString(authentication.getName());
//        UserEntity userEntity = userRepository.findByUserId(userId);
//        return "hello " + userEntity.getUsername();
//    }

    public String signup(UserDto userDto) {

        UserEntity userEntity = userRepository.findByEmail(userDto.getEmail());

        if(userEntity != null) {
            return "User already exists with this username";
        }

        userEntity = new UserEntity();

        userEntity.setEmail(userDto.getEmail());
        userEntity.setPassword(userDto.getPassword());
        userEntity.setFirstname(userDto.getFirstname());
        userEntity.setLastname(userDto.getLastname());
        userEntity.setContact_no(userDto.getContact_no());

        userRepository.save(userEntity);

        return "User Created Successfully";
    }
}
