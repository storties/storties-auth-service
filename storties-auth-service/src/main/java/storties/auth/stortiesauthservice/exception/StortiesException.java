package storties.auth.stortiesauthservice.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import storties.auth.stortiesauthservice.error.ErrorCodes;

@Getter
@RequiredArgsConstructor
public class StortiesException extends RuntimeException{

    private final ErrorCodes errorProperty;
}
