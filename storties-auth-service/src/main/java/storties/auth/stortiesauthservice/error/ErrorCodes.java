package storties.auth.stortiesauthservice.error;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCodes {

    INTERNAL_SERVER_ERROR(ErrorStatus.INTERNAL_SERVER_ERROR, "서버 에러", 1),

    PASSWORD_MISMATCH(ErrorStatus.UNAUTHORIZED, "비밀번호 불일치", 1);

    private final int status;

    private final String message;

    private final int sequence;
}
