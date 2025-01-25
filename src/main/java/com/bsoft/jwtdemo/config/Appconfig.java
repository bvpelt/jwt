package com.bsoft.jwtdemo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@Slf4j
@Configuration
public class Appconfig {


    @Bean
    public PasswordEncoder passwordEncoder() {
        log.trace("Starting bCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }

}
