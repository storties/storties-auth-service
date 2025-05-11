package storties.auth.stortiesauthservice.persistence;

import jakarta.persistence.Entity;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Column;
import lombok.Getter;
import lombok.NoArgsConstructor;
import storties.auth.stortiesauthservice.persistence.type.OauthProvider;
import storties.auth.stortiesauthservice.persistence.type.Role;

import java.time.LocalDateTime;

@Entity
@NoArgsConstructor
@Getter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    private String email;

    private String name;

    @Column(columnDefinition = "VARCHAR(60)")
    private String password;

    @Column(columnDefinition = "VARCHAR(20)")
    private Role role;

    @Column(columnDefinition = "VARCHAR(20)", name = "oauth_provider")
    private OauthProvider oauthProvider;

    @Column(name = "oauth_provider_id")
    private String oauthProviderId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
