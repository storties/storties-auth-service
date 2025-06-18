package storties.auth.stortiesauthservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.global.exception.StortiesException;
import storties.auth.stortiesauthservice.global.exception.error.ErrorCodes;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.persistence.type.AuthProvider;
import storties.auth.stortiesauthservice.persistence.type.Role;
import storties.auth.stortiesauthservice.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.service.dto.response.AllTokenResponse;
import storties.auth.stortiesauthservice.service.util.JwtUtil;

@Service
@RequiredArgsConstructor
@Transactional
public class RegisterLocalUserService {

    private final UserJpaRepository userJpaRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtUtil jwtUtil;

    public AllTokenResponse execute(AuthUserRequest request) {
        if(userJpaRepository.existsByEmail(request.getEmail())) {
            throw ErrorCodes.EMAIL_ALREADY_EXIST.throwException();
        }

        User user = userJpaRepository.save(User.builder()
                .authProvider(AuthProvider.LOCAL)
                .email(request.getEmail())
                .role(Role.USER)
                .password(passwordEncoder.encode(request.getPassword()))
                .build());

        return jwtUtil.createAllToken(user.getId(), user.getEmail(), user.getRole());
    }
}
