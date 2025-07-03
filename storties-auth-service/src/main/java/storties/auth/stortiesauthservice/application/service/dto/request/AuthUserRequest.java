package storties.auth.stortiesauthservice.application.service.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthUserRequest {

    private String email;

    private String password;
}
