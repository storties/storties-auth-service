package storties.auth.stortiesauthservice.infrastructure.grpc;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import java.util.Optional;
import javax.annotation.Nullable;
import net.devh.boot.grpc.server.security.authentication.GrpcAuthenticationReader;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class GrpcTokenAuthenticationReader implements GrpcAuthenticationReader {
    private static final Metadata.Key<String> AUTHORIZATION_HEADER =
        Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final String BEARER_PREFIX = "Bearer ";

    @Nullable
    @Override
    public Authentication readAuthentication(ServerCall<?, ?> call, Metadata headers) throws AuthenticationException {
        return null;
    }
}
