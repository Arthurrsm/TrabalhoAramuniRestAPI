package com.example.TrabalhoAramuniRestAPI.repository;

import com.example.TrabalhoAramuniRestAPI.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRepository extends MongoRepository<User, String> {
    User findByUsername(String username);
}
