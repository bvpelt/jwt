package com.bsoft.jwtdemo.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
@AllArgsConstructor
@Getter
@Setter
public class LoginResponse {
    private String jwtToken;
    private String username;
    private List<String> role;
}