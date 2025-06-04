package storties.auth.stortiesauthservice.authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import storties.auth.stortiesauthservice.authentication.token.Token;
import storties.auth.stortiesauthservice.persistence.type.Role;
import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 토큰 생성 밑 파싱
 */

// todo 리펙토링 할게 참 많다....
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final RedisTemplate<String, String> redisTemplate;

    private final JwtProperties jwtProperties;

    /**
     * 토큰 생성 시 Role은 String 형태로 저장됨
     * @param id 아이디
     * @param email 유저 이름
     * @param role 권한
     * @return 토큰
     */
    public Map<String, Object> createAccessToken(Long id, String email, Role role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtProperties.ROLE, String.valueOf(role));
        claims.put(JwtProperties.EMAIL, email);
        claims.put(JwtProperties.ID, id);
        claims.put(JwtProperties.TOKEN_TYPE, String.valueOf(Token.ACCESS_TOKEN));

        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

        long validity = jwtProperties.ACCESS_TOKEN_EXPIRES_AT;
        Date now = new Date();
        Date exp = new Date(now.getTime() + validity);

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp).signWith(key)
                .compact();

        Map<String, Object> response = new HashMap<>();
        response.put(JwtProperties.TOKEN, token);
        response.put(JwtProperties.EXPIRES_IN, validity / 1000);
        response.put(JwtProperties.EXPIRES_AT, exp);

        return response;
    }

    /**
     * 리프레시 토큰 생성 및 redis에 저장
     * @param id 아이디
     * @return 리프레시 토큰
     */
    public Map<String, Object> createRefreshToken(Long id) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtProperties.ID, id);
        claims.put(JwtProperties.TOKEN_TYPE, String.valueOf(Token.REFRESH_TOKEN));
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

        Date now = new Date();
        long validity = 14 * 24 * 60 * 60 * 1000L;
        Date exp = new Date(now.getTime() + validity);

        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(key)
                .compact();

        String redisKey = "RT:" + id;
        redisTemplate.opsForValue().set(redisKey, refreshToken, Duration.ofDays(14));

        String token = Jwts
                .builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(key)
                .compact();

        Map<String, Object> response = new HashMap<>();
        response.put(JwtProperties.TOKEN, token);
        response.put(JwtProperties.EXPIRES_IN, validity / 1000);
        response.put(JwtProperties.EXPIRES_AT, exp);

        return response;
    }
}
