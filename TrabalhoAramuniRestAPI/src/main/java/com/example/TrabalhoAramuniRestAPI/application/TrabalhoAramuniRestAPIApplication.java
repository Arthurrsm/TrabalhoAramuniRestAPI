package com.example.TrabalhoAramuniRestAPI.application;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

    @SpringBootApplication(scanBasePackages = {"com.example"})
    @EnableMongoRepositories("com.example.TrabalhoAramuniRestAPI.repository")
    public class TrabalhoAramuniRestAPIApplication {

        public static void main(String[] args) {
            SpringApplication.run(TrabalhoAramuniRestAPIApplication.class, args);
        }

    }
