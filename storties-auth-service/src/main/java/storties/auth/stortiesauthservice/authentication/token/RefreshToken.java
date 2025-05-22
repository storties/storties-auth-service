package storties.auth.stortiesauthservice.authentication.token;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;
import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(value = "token", timeToLive = 1209600) // 임시
public class RefreshToken {
    @Id
    private String userId;

    private String token;

    private LocalDateTime issuedAt;
}
