package com.example.springshop.service;

import com.example.springshop.dto.UserDTO;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService { // для секьюрити

    boolean save(UserDTO userDTO);
}
