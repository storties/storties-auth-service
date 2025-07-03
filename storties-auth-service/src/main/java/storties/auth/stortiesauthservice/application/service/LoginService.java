package storties.auth.stortiesauthservice.application.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.application.service.util.JwtUtil;
import storties.auth.stortiesauthservice.global.exception.error.ErrorCodes;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.application.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.application.service.dto.response.AllTokenResponse;

@Service
@RequiredArgsConstructor
@Transactional
public class LoginService {

    private final PasswordEncoder passwordEncoder;

    private final UserJpaRepository userJpaRepository;

    private final JwtUtil jwtUtil;

    public AllTokenResponse execute(AuthUserRequest authUserRequest) {

        User user = userJpaRepository.findByEmail(authUserRequest.getEmail())
                .orElseThrow(ErrorCodes.EMAIL_ALREADY_EXIST::throwException);

        if(!passwordEncoder.matches(authUserRequest.getPassword(), user.getPassword())) {
            throw ErrorCodes.PASSWORD_MISMATCH.throwException();
        }

        return jwtUtil.createAllToken(user.getId(), user.getRole());
    }
}
