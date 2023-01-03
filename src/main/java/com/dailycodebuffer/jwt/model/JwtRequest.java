package com.dailycodebuffer.jwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtRequest {
    //it is a model to encapsulate the jwt request
    private String username;
    private String password;
}
