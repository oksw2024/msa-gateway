package osj.javat.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import osj.javat.util.JwtUtil;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<Config> {

    @Autowired
    private JwtUtil jwtUtil;

    public JwtAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return this.onError(exchange, "Authorization header is missing or invalid", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            if (!jwtUtil.validateToken(token)) {
                return this.onTokenExpired(exchange, "Token expired or invalid", HttpStatus.UNAUTHORIZED);
            }

            // 토큰이 유효한 경우
            String username = jwtUtil.getUsernameFromToken(token);
            exchange.getRequest().mutate().header("X-Authenticated-User", username).build();

            return chain.filter(exchange);
        };
    }

    // 요청에 문제가 있는 경우(Authorization 헤더 누락, 유효하지 않은 헤더)
    private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    // 토큰이 만료되었거나 잘못된 경우
    private Mono<Void> onTokenExpired(ServerWebExchange exchange, String error, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().add(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"Access Token\", error=\"invalid_token\", error_description=\"Token expired\"");
        return exchange.getResponse().setComplete();
    }
}
