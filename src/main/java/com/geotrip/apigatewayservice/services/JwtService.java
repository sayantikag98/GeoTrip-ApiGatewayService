package com.geotrip.apigatewayservice.services;

import java.util.Date;

public interface JwtService {

    String extractEmail(String token);

    Date extractExpiration(String token);

    String extractRole(String token);

    boolean isTokenExpired(String token);
}
