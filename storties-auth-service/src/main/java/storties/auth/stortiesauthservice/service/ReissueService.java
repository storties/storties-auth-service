package storties.auth.stortiesauthservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.authentication.JwtTokenProvider;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.service.dto.response.AccessTokenResponse;
import storties.auth.stortiesauthservice.service.util.JwtTokenUtil;

import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional
public class ReissueService {

    private final UserJpaRepository userJpaRepository;

    private final JwtTokenProvider jwtTokenProvider;

    private final JwtTokenUtil jwtTokenUtil;

    public AccessTokenResponse execute(String token){

        if(!jwtTokenProvider.validateRefreshToken(token)) {
            throw new IllegalArgumentException();
        }

        User user = userJpaRepository.findById(jwtTokenProvider.getId(token))
                .orElseThrow(RuntimeException::new);

        return jwtTokenUtil.createAccessToken(user.getId(), user.getEmail(), user.getRole());
    }
}
