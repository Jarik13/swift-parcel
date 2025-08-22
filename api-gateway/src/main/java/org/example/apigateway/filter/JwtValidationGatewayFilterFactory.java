package org.example.apigateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Objects;

@Component
public class JwtValidationGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {
    private final WebClient webClient;

    public JwtValidationGatewayFilterFactory(WebClient.Builder webClient,
                                             @Value("${auth.service.url}") String authServiceUrl) {
        this.webClient = webClient.baseUrl(authServiceUrl).build();
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String token = extractTokenFromCookie(exchange.getRequest());

            if (token == null || token.isBlank()) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            return webClient.get()
                    .uri("/auth/validate")
                    .cookie("access_token", token)
                    .retrieve()
                    .bodyToMono(String.class)
                    .flatMap(userId -> {
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .header("X-User-Id", userId)
                                .build();

                        return chain.filter(exchange.mutate().request(mutatedRequest).build());
                    })
                    .onErrorResume(ex -> {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }

    private String extractTokenFromCookie(ServerHttpRequest request) {
        return request.getCookies().getFirst("access_token") != null
                ? Objects.requireNonNull(request.getCookies().getFirst("access_token")).getValue()
                : null;
    }
}
