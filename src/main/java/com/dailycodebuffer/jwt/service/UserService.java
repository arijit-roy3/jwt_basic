package com.dailycodebuffer.jwt.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        //Logic to get the user form the Database
        //here we are using hardcoded values as there is no db layer
        //we are overriding the default method loadUserByUsername to find the user
        //'User' is the default entity provided by spring core
        return new User("admin","password",new ArrayList<>());
    }
}
