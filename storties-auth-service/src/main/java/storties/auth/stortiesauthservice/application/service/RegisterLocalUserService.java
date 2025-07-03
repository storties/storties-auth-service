package storties.auth.stortiesauthservice.application.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import storties.auth.stortiesauthservice.application.service.dto.request.AuthUserRequest;
import storties.auth.stortiesauthservice.application.service.util.JwtUtil;
import storties.auth.stortiesauthservice.global.exception.error.ErrorCodes;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.persistence.type.AuthProvider;
import storties.auth.stortiesauthservice.persistence.type.Role;
import storties.auth.stortiesauthservice.application.service.dto.response.AllTokenResponse;

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

        return jwtUtil.createAllToken(user.getId(), user.getRole());
    }
}
