package storties.auth.stortiesauthservice.global.authentication;

import org.springframework.security.core.context.SecurityContextHolder;

public class AuthenticatedUserProvider {

    public Long getCurrentUserId() {
        return Long.valueOf(SecurityContextHolder.getContext().getAuthentication().getName());
    }
}
