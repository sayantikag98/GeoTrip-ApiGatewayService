package com.geotrip.apigatewayservice.filters;


import com.geotrip.apigatewayservice.services.JwtService;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public int getOrder() {
        return -1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        try{
            ServerHttpRequest request = exchange.getRequest();

            System.out.println("uri "+request.getURI());
            String path = request.getURI().getPath();


            //skip auth for these endpoints
            if(isPublicRoute(path)) {
                return chain.filter(exchange);
            }

            String authorization = request.getHeaders().getFirst("Authorization");

            if(authorization == null || !authorization.startsWith("Bearer ")) {
                throw new Exception();
            }

            String token = authorization.substring(7);

            if(jwtService.isTokenExpired(token)) {
                throw new Exception();
            }

            String email = jwtService.extractEmail(token);
            String role = jwtService.extractRole(token);
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Email", email)
                    .header("X-User-Role", "ROLE_"+role)
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        }
        catch(Exception e){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    private boolean isPublicRoute(String path) {
        return path.matches("^/api/v1/auth/register/(passenger|driver)$") || path.equals("/api/v1/auth/login");
    }
}
