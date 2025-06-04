package storties.auth.stortiesauthservice.service.util;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import storties.auth.stortiesauthservice.authentication.JwtProvider;
import storties.auth.stortiesauthservice.persistence.type.Role;
import storties.auth.stortiesauthservice.service.dto.response.AccessTokenResponse;
import storties.auth.stortiesauthservice.service.dto.response.AllTokenResponse;

import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final JwtProvider jwtProvider;

    static private final String TOKEN = "token";

    static private final String EXPIRES_AT = "expiresAt";


    public AllTokenResponse createAllToken(Long id, String email, Role role) {
        Map<String, Object> refreshToken = jwtProvider.createRefreshToken(id);
        Map<String, Object> accessToken = jwtProvider.createAccessToken(id, email, role);

        return AllTokenResponse.builder()
                .accessToken((String) accessToken.get(TOKEN))
                .accessTokenExpiresAt((Date) accessToken.get(EXPIRES_AT))
                .refreshToken((String) refreshToken.get(TOKEN))
                .refreshTokenExpiresAt((Date) refreshToken.get(EXPIRES_AT))
                .build();
    }

    public AccessTokenResponse createAccessToken(Long id, String email, Role role) {
        Map<String, Object> accessToken = jwtProvider.createAccessToken(id, email, role);

        return AccessTokenResponse.builder()
                .accessToken((String) accessToken.get(TOKEN))
                .accessTokenExpiresAt((Date) accessToken.get(EXPIRES_AT))
                .build();
    }
}
