package storties.auth.stortiesauthservice.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import storties.auth.stortiesauthservice.service.LoginService;
import storties.auth.stortiesauthservice.service.RegisterLocalUserService;
import storties.auth.stortiesauthservice.service.ReissueService;
import storties.auth.stortiesauthservice.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.service.dto.response.AccessTokenResponse;
import storties.auth.stortiesauthservice.service.dto.response.JwtTokenResponse;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final LoginService loginService;
    private final RegisterLocalUserService registerLocalUserService;
    private final ReissueService reissueService;

    @PostMapping("/login")
    public ResponseEntity<JwtTokenResponse> login(@RequestBody AuthUserRequest request) {
        JwtTokenResponse response = loginService.execute(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<JwtTokenResponse> register(@RequestBody AuthUserRequest request) {
        JwtTokenResponse response = registerLocalUserService.execute(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reissue")
    public ResponseEntity<AccessTokenResponse> reissue(@RequestHeader("Authorization") String refreshToken) {
        // Bearer prefix 제거
        String token = refreshToken.replace("Bearer ", "");
        AccessTokenResponse response = reissueService.execute(token);
        return ResponseEntity.ok(response);
    }
}
