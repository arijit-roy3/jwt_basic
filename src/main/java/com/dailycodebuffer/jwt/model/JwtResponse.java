package com.dailycodebuffer.jwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    //it is a model to encapsulate the jwt response
    private String jwtToken;
}
