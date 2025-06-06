package storties.auth.stortiesauthservice.service.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import java.util.Date;

@Getter
@Builder
@AllArgsConstructor
public class AllTokenResponse {

    private String accessToken;

    private Date accessTokenExpiresAt;

    private String refreshToken;

    private Date refreshTokenExpiresAt;
}
