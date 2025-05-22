package storties.auth.stortiesauthservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.authentication.JwtTokenProvider;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.persistence.type.AuthProvider;
import storties.auth.stortiesauthservice.persistence.type.Role;
import storties.auth.stortiesauthservice.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.service.dto.response.AllTokenResponse;
import storties.auth.stortiesauthservice.service.util.JwtTokenUtil;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional
public class RegisterLocalUserService {

    private final UserJpaRepository userJpaRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtTokenUtil jwtTokenUtil;

    public AllTokenResponse execute(AuthUserRequest request) {
        if(userJpaRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException();
        }

        User user = userJpaRepository.save(User.builder()
                .authProvider(AuthProvider.LOCAL)
                .email(request.getEmail())
                .role(Role.USER)
                .password(passwordEncoder.encode(request.getPassword()))
                .build());

        return jwtTokenUtil.createAllToken(user.getId(), user.getEmail(), user.getRole());
    }
}
