package storties.auth.stortiesauthservice.authentication;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import storties.auth.stortiesauthservice.persistence.type.Role;

import javax.crypto.SecretKey;
import java.util.List;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {
    private final String secret = "secretKeyfHeljfaosdjASDDFeefffHJFTDCVdsaklfjalsdkfjlasdkjfaldkf";

    /**
     * 토큰 생성 시 Role은 String 형태로 저장됨
     * @param id 아이디
     * @param userName 유저 이름
     * @param role 권한
     * @return 토큰
     */
    public String createToken(Long id, String userName, Role role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", String.valueOf(role));
        claims.put("userName", userName);
        claims.put("id", id);

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

    public Authentication getAuthentication(String token) {
        String username = getUsername(token);
        return new UsernamePasswordAuthenticationToken(username, "", List.of());
    }

    public String getUsername(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(token).getBody().get("userName", String.class);
    }

    public String getRole(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(token).getBody().get("role", String.class);
    }

    public Long getId(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(token).getBody().get("id", Long.class);
    }

    public boolean validateToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
