package storties.auth.stortiesauthservice.global.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import storties.auth.stortiesauthservice.global.exception.error.ErrorCodes;

@Getter
@RequiredArgsConstructor
public class StortiesException extends RuntimeException{

    private final ErrorCodes errorProperty;
}
