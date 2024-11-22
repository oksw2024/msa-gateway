package osj.javat.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;
    
    @Value("${jwt.accessTokenExpirationTime}")
	private Long jwtAccessTokenExpirationTime;
    
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
    }
    
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

 // 토큰 만료 여부 확인
 	public boolean validateToken(String accessToken) {
         try {
             Jws<Claims> claims = Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(accessToken);
             return !claims.getPayload().getExpiration().before(new Date());
         } catch (ExpiredJwtException e) {
         	return false;
         } catch (SignatureException e) {
         	return false;
         } catch (Exception e) {
             return false;
         }
     }

 	public String getUsernameFromToken(String accessToken) {
        String info = Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(accessToken).getPayload()
                .getSubject();
        return info;
    }
}
