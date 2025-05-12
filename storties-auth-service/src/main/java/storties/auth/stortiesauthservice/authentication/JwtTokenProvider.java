package storties.auth.stortiesauthservice.authentication;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import storties.auth.stortiesauthservice.persistence.type.Role;
import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.List;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 토큰 생성 밑 파싱
 */
@Component
public class JwtTokenProvider {
    private final String secret = "secretKeyfHeljfaosdjASDDFeefffHJFTDCVdsaklfjalsdkfjlasdkjfaldkf";

    private final RedisTemplate<String, String> redisTemplate;

    public JwtTokenProvider(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 토큰 생성 시 Role은 String 형태로 저장됨
     * @param id 아이디
     * @param userName 유저 이름
     * @param role 권한
     * @return 토큰
     */
    public String createAccessToken(Long id, String userName, Role role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", String.valueOf(role));
        claims.put("userName", userName);
        claims.put("id", id);
        claims.put("tokenType", String.valueOf(Token.ACCESS_TOKEN));

        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        Date now = new Date();
        long validity = 1000 * 15 * 60;
        Date exp = new Date(now.getTime() + validity);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();
    }

    /**
     * 리프레시 토큰 생성 및 redis에 저장
     * @param id 아이디
     * @return 리프레시 토큰
     */
    public String createRefreshToken(Long id) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", id);
        claims.put("tokenType", String.valueOf(Token.REFRESH_TOKEN));
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 14 * 24 * 60 * 60 * 1000L)) // 임시
                .signWith(SignatureAlgorithm.HS256, key) // 임시
                .compact();

        String redisKey = "RT:" + id;
        redisTemplate.opsForValue().set(redisKey, refreshToken, Duration.ofDays(14));

        return refreshToken;
    }

    /**
     * 권한 가져오기
     * @param accessToken - 엑세스 토큰
     * @return 권한
     */
    public Authentication getAuthentication(String accessToken) {
        String username = getUsername(accessToken);
        return new UsernamePasswordAuthenticationToken(username, "", List.of());
    }

    public String getUsername(String accessToken) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get("userName", String.class);
    }

    public String getRole(String accessToken) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get("role", String.class);
    }

    public Long getId(String accessToken) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get("id", Long.class);
    }

    public boolean validateAccessToken(String accessToken) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

            JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build();

            Date expiration = parser.parseClaimsJws(accessToken).getBody().getExpiration();
            boolean isExpired = expiration.before(new Date());

            if (isExpired) return false;

            String tokenType = parser.parseClaimsJws(accessToken).getBody().get("tokenType", String.class);

            return tokenType.equals("ACCESS_TOKEN");
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // todo [401 expired] 추가 해야함
    public boolean validateRefreshToken(String refreshToken) { // Expired 확인 필요(수정 필요)
        try {
            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

            JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build();

            Date expiration = parser.parseClaimsJws(refreshToken).getBody().getExpiration();
            boolean isExpired = expiration.before(new Date());

            if (isExpired) return false;

            String tokenType = parser.parseClaimsJws(refreshToken).getBody().get("tokenType", String.class);
            return tokenType.equals("REFRESH_TOKEN");
        } catch (JwtException e) {
            return false;
        }
    }
}
