package storties.auth.stortiesauthservice.application.service.dto.response;

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
