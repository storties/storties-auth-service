package storties.auth.stortiesauthservice.service;

import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@Service
public class Oauth2RedirectService {
    public Map<String, String> execute(String provider) {
        String redirectUri = UriComponentsBuilder.fromUriString("http://localhost:8080/oauth2/authorization/" + provider)
                .build()
                .toString();

        return Map.of("url", redirectUri);
    }
}
