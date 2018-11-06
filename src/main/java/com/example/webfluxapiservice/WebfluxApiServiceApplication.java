package com.example.webfluxapiservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.config.EnableMongoAuditing;
import org.springframework.data.mongodb.repository.config.EnableReactiveMongoRepositories;
import springfox.documentation.swagger2.annotations.EnableSwagger2WebFlux;

/**
 * @author Anthony Jinhyuk Kim
 * @version 1.0.0
 * @since 2018-11-06
 */
@SpringBootApplication
@EnableSwagger2WebFlux
@EnableMongoAuditing
@EnableReactiveMongoRepositories
public class WebfluxApiServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebfluxApiServiceApplication.class, args);
    }
}
