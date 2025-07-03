package storties.auth.stortiesauthservice.application.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.application.service.dto.response.AccessTokenResponse;
import storties.auth.stortiesauthservice.application.service.util.JwtUtil;
import storties.auth.stortiesauthservice.global.authentication.JwtTokenParser;
import storties.auth.stortiesauthservice.global.exception.error.ErrorCodes;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;

@Service
@RequiredArgsConstructor
@Transactional
public class ReissueService {

    private final UserJpaRepository userJpaRepository;

    private final JwtUtil jwtUtil;

    private final JwtTokenParser jwtTokenParser;

    public AccessTokenResponse execute(String refreshToken){
        String token = refreshToken.replace("Bearer ", "");

        if(!jwtTokenParser.validateRefreshToken(token)) {
            throw new IllegalArgumentException();
        }

        User user = userJpaRepository.findById(jwtTokenParser.getId(token))
                .orElseThrow(ErrorCodes.USER_NOT_FOUND::throwException);

        return jwtUtil.createAccessToken(user.getId(), user.getRole());
    }
}
