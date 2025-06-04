package storties.auth.stortiesauthservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.authentication.JwtParser;
import storties.auth.stortiesauthservice.authentication.JwtProvider;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.service.dto.response.AccessTokenResponse;
import storties.auth.stortiesauthservice.service.util.JwtUtil;

@Service
@RequiredArgsConstructor
@Transactional
public class ReissueService {

    private final UserJpaRepository userJpaRepository;

    private final JwtProvider jwtProvider;

    private final JwtUtil jwtUtil;

    private final JwtParser jwtParser;

    public AccessTokenResponse execute(String token){

        if(!jwtParser.validateRefreshToken(token)) {
            throw new IllegalArgumentException();
        }

        User user = userJpaRepository.findById(jwtParser.getId(token))
                .orElseThrow(RuntimeException::new);

        return jwtUtil.createAccessToken(user.getId(), user.getEmail(), user.getRole());
    }
}
