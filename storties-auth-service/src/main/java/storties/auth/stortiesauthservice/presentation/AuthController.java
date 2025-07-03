package storties.auth.stortiesauthservice.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import storties.auth.stortiesauthservice.application.service.LoginService;
import storties.auth.stortiesauthservice.application.service.Oauth2RedirectService;
import storties.auth.stortiesauthservice.application.service.RegisterLocalUserService;
import storties.auth.stortiesauthservice.application.service.ReissueService;
import storties.auth.stortiesauthservice.application.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.application.service.dto.response.AccessTokenResponse;
import storties.auth.stortiesauthservice.application.service.dto.response.AllTokenResponse;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final LoginService loginService;
    private final RegisterLocalUserService registerLocalUserService;
    private final ReissueService reissueService;
    private final Oauth2RedirectService redirectService;

    @PostMapping("/login")
    public AllTokenResponse login(@RequestBody AuthUserRequest request) {
        return loginService.execute(request);
    }

    @PostMapping("/register")
    public AllTokenResponse register(@RequestBody AuthUserRequest request) {
        return registerLocalUserService.execute(request);
    }

    @PostMapping("/reissue")
    public AccessTokenResponse reissue(@RequestHeader("Authorization") String refreshToken) {
        return reissueService.execute(refreshToken);
    }

    @PostMapping("/oauth/{provider}")
    public Map<String, String> redirectToProvider(@PathVariable String provider) {
        return redirectService.execute(provider);
    }
}
