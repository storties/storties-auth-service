package storties.auth.stortiesauthservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.authentication.JwtTokenProvider;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.service.dto.response.AllTokenResponse;
import storties.auth.stortiesauthservice.service.util.JwtTokenUtil;

import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class LoginService {

    private final PasswordEncoder passwordEncoder;

    private final UserJpaRepository userJpaRepository;

    private final JwtTokenUtil jwtTokenUtil;

    public AllTokenResponse execute(AuthUserRequest authUserRequest){

        Optional<User> user = Optional.of(userJpaRepository.findByEmail(authUserRequest.getEmail())
                .orElseThrow());

        if(!passwordEncoder.matches(authUserRequest.getPassword(), user.get().getPassword())) {
            throw new IllegalArgumentException("비밀번호 불일치");
        }

        return jwtTokenUtil.createAllToken(user.get().getId(), user.get().getEmail(), user.get().getRole());
    }
}
