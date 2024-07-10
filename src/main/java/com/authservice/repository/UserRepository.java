package com.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.authservice.models.User;


public interface UserRepository extends JpaRepository<User , Long>{
    
    public User findByEmail(String email);

}
