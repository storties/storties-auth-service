package storties.auth.stortiesauthservice.application.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import storties.auth.stortiesauthservice.application.service.util.JwtUtil;
import storties.auth.stortiesauthservice.persistence.User;
import storties.auth.stortiesauthservice.persistence.repository.UserJpaRepository;
import storties.auth.stortiesauthservice.persistence.type.AuthProvider;
import storties.auth.stortiesauthservice.persistence.type.Role;
import storties.auth.stortiesauthservice.application.service.dto.response.AllTokenResponse;

@Service
@RequiredArgsConstructor
public class Oauth2AuthenticationService {

    private final JwtUtil jwtUtil;

    private final UserJpaRepository userJpaRepository;

    public AllTokenResponse execute(Authentication authentication) {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String providerId = oAuth2User.getAttribute("sub");

        User user = userJpaRepository.findByEmail(email)
                .orElseGet(() -> userJpaRepository.save(User.builder()
                        .role(Role.USER)
                        .email(email)
                        .oauthProviderId(providerId)
                        .authProvider(AuthProvider.GOOGLE)
                        .build()));

        return jwtUtil.createAllToken(user.getId(), user.getRole());
    }
}
