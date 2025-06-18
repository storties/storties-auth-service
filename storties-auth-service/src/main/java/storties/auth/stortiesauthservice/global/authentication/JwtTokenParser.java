package storties.auth.stortiesauthservice.global.authentication;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import storties.auth.stortiesauthservice.global.exception.error.ErrorCodes;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenParser {

    private final JwtProperties jwtProperties;

    private final JwtParser jwtParser;

    public JwtTokenParser(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());
        this.jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
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

    public String getEmailByAccessToken(String accessToken) {
        return jwtParser.parseClaimsJws(accessToken).getBody().get(JwtProperties.EMAIL, String.class);
    }

    public String getRoleByAccessToken(String accessToken) {
        return jwtParser.parseClaimsJws(accessToken).getBody().get(JwtProperties.ROLE, String.class);
    }

    public Long getId(String accessToken) {
        return jwtParser.parseClaimsJws(accessToken).getBody().get(JwtProperties.ID, Long.class);
    }

    public boolean validateAccessToken(String accessToken) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

            io.jsonwebtoken.JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build();

            Date expiration = parser.parseClaimsJws(accessToken).getBody().getExpiration();
            boolean isExpired = expiration.before(new Date());

            if (isExpired) throw ErrorCodes.TOKEN_EXPIRED.throwException();

            String tokenType = parser.parseClaimsJws(accessToken).getBody().get(JwtProperties.TOKEN_TYPE, String.class);

            return tokenType.equals(JwtProperties.ACCESS_TOKEN);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean validateRefreshToken(String refreshToken) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtProperties.SECRET.getBytes());

            io.jsonwebtoken.JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build();

            Date expiration = parser.parseClaimsJws(refreshToken).getBody().getExpiration();
            boolean isExpired = expiration.before(new Date());

            if (isExpired) throw ErrorCodes.TOKEN_EXPIRED.throwException();

            String tokenType = parser.parseClaimsJws(refreshToken).getBody().get(JwtProperties.TOKEN_TYPE, String.class);
            return tokenType.equals(JwtProperties.REFRESH_TOKEN);
        } catch (JwtException e) {
            return false;
        }
    }
}
