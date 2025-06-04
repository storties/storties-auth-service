package storties.auth.stortiesauthservice.authentication;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtParser {

    private final RedisTemplate<String, String> redisTemplate;

    private final JwtProperties jwtProperties;

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
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

        io.jsonwebtoken.JwtParser parser = Jwts.parserBuilder() // 이부분이 겹치네.. 메소드로 따로 만들 것
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get(JwtProperties.EMAIL, String.class);
    }

    public String getRoleByAccessToken(String accessToken) {
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

        io.jsonwebtoken.JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get(JwtProperties.ROLE, String.class);
    }

    public Long getId(String accessToken) {
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

        io.jsonwebtoken.JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(accessToken).getBody().get(JwtProperties.ID, Long.class);
    }

    public boolean validateAccessToken(String accessToken) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

            io.jsonwebtoken.JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build();

            Date expiration = parser.parseClaimsJws(accessToken).getBody().getExpiration();
            boolean isExpired = expiration.before(new Date());

            if (isExpired) return false;

            String tokenType = parser.parseClaimsJws(accessToken).getBody().get(JwtProperties.TOKEN_TYPE, String.class);

            return tokenType.equals(JwtProperties.ACCESS_TOKEN);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // todo [401 expired] 추가 해야함
    public boolean validateRefreshToken(String refreshToken) { // Expired 확인 필요(수정 필요)
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

            io.jsonwebtoken.JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build();

            Date expiration = parser.parseClaimsJws(refreshToken).getBody().getExpiration();
            boolean isExpired = expiration.before(new Date());

            if (isExpired) return false;

            String tokenType = parser.parseClaimsJws(refreshToken).getBody().get(JwtProperties.TOKEN_TYPE, String.class);
            return tokenType.equals(JwtProperties.REFRESH_TOKEN);
        } catch (JwtException e) {
            return false;
        }
    }
}
