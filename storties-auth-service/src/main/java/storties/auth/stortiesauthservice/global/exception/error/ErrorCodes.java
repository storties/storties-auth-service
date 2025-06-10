package storties.auth.stortiesauthservice.global.exception.error;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCodes {


    PASSWORD_MISMATCH(ErrorStatus.UNAUTHORIZED, "비밀번호 불일치", 1),

    USER_NOT_FOUND(ErrorStatus.NOT_FOUND, "유저를 찾지 못했습니다.", 1),

    INTERNAL_SERVER_ERROR(ErrorStatus.INTERNAL_SERVER_ERROR, "서버 에러", 1);

    private final int status;

    private final String message;

    private final int sequence;
}
