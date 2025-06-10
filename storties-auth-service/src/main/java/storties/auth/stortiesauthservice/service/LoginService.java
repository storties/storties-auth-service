package storties.auth.stortiesauthservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.global.exception.error.ErrorCodes;
import storties.auth.stortiesauthservice.global.exception.StortiesException;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.service.dto.response.AllTokenResponse;
import storties.auth.stortiesauthservice.service.util.JwtUtil;

@Service
@RequiredArgsConstructor
@Transactional
public class LoginService {

    private final PasswordEncoder passwordEncoder;

    private final UserJpaRepository userJpaRepository;

    private final JwtUtil jwtUtil;

    public AllTokenResponse execute(AuthUserRequest authUserRequest) {

        User user = userJpaRepository.findByEmail(authUserRequest.getEmail())
                .orElseThrow(() -> new StortiesException(ErrorCodes.USER_NOT_FOUND));

        if(!passwordEncoder.matches(authUserRequest.getPassword(), user.getPassword())) {
            throw new StortiesException(ErrorCodes.PASSWORD_MISMATCH);
        }

        return jwtUtil.createAllToken(user.getId(), user.getEmail(), user.getRole());
    }
}
