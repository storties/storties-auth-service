package storties.auth.stortiesauthservice.authentication;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import storties.auth.stortiesauthservice.authentication.token.Token;
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

// todo 리펙토링 할게 참 많다....
@Component
public class JwtTokenProvider {
    static private final String secret = "secretKeyfHeljfaosdjASDDFeefffHJFTDCVdsaklfjalsdkfjlasdkjfaldkf";

    static private final String ROLE = "role";

    static private final String EMAIL = "email";

    static private final String ID = "id";

    static private final String TOKEN_TYPE = "tokenType";

    static private final String TOKEN = "token";

    static private final String EXPIRES_IN = "expiresIn";

    static private final String EXPIRES_AT = "expiresAt";

    static private final String ACCESS_TOKEN = "ACCESS_TOKEN";

    static private final String REFRESH_TOKEN = "REFRESH_TOKEN";

    private final RedisTemplate<String, String> redisTemplate;

    public JwtTokenProvider(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 토큰 생성 시 Role은 String 형태로 저장됨
     * @param id 아이디
     * @param email 유저 이름
     * @param role 권한
     * @return 토큰
     */
    public Map<String, Object> createAccessToken(Long id, String email, Role role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(ROLE, String.valueOf(role));
        claims.put(EMAIL, email);
        claims.put(ID, id);
        claims.put(TOKEN_TYPE, String.valueOf(Token.ACCESS_TOKEN));

        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        Date now = new Date();
        long validity = 1000 * 15 * 60;
        Date exp = new Date(now.getTime() + validity);

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();

        Map<String, Object> response = new HashMap<>();
        response.put(TOKEN, token);
        response.put(EXPIRES_IN, validity / 1000);
        response.put(EXPIRES_AT, exp);

        return response;
    }

    /**
     * 리프레시 토큰 생성 및 redis에 저장
     * @param id 아이디
     * @return 리프레시 토큰
     */
    public Map<String, Object> createRefreshToken(Long id) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(ID, id);
        claims.put(TOKEN_TYPE, String.valueOf(Token.REFRESH_TOKEN));
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        Date now = new Date();
        long validity = 14 * 24 * 60 * 60 * 1000L;
        Date exp = new Date(now.getTime() + validity);

        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(SignatureAlgorithm.HS256, key) // 임시
                .compact();

        String redisKey = "RT:" + id;
        redisTemplate.opsForValue().set(redisKey, refreshToken, Duration.ofDays(14));

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();

        Map<String, Object> response = new HashMap<>();
        response.put(TOKEN, token);
        response.put(EXPIRES_IN, validity / 1000);
        response.put(EXPIRES_AT, exp);

        return response;
    }

    /**
     * 권한 가져오기
     * @param accessToken 엑세스 토큰
     * @return 권한
     */
    public Authentication getAuthentication(String accessToken) {
        String username = getEmailByAccessToken(accessToken);
        return new UsernamePasswordAuthenticationToken(username, "", List.of());
    }

    public String getEmailByAccessToken(String accessToken) { // todo 토큰 파싱 해서 정보 얻는 부분은 클래스 분리하자
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder() // 이부분이 겹치네.. 메소드로 따로 만들 것
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get(EMAIL, String.class);
    }

    public String getRoleByAccessToken(String accessToken) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get(ROLE, String.class);
    }

    public Long getId(String accessToken) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get(ID, Long.class);
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

            String tokenType = parser.parseClaimsJws(accessToken).getBody().get(TOKEN_TYPE, String.class);

            return tokenType.equals(ACCESS_TOKEN);
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

            String tokenType = parser.parseClaimsJws(refreshToken).getBody().get(TOKEN_TYPE, String.class);
            return tokenType.equals(REFRESH_TOKEN);
        } catch (JwtException e) {
            return false;
        }
    }
}
