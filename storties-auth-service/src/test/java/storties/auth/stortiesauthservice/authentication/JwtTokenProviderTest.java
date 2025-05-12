package storties.auth.stortiesauthservice.authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import storties.auth.stortiesauthservice.persistence.type.Role;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtTokenProviderTest {

    private RedisTemplate<String, String> mockRedisTemplate;
    private ValueOperations<String, String> mockValueOperations;
    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        mockRedisTemplate = mock(RedisTemplate.class);
        mockValueOperations = mock(ValueOperations.class);

        when(mockRedisTemplate.opsForValue()).thenReturn(mockValueOperations);

        jwtTokenProvider = new JwtTokenProvider(mockRedisTemplate);
    }

    @Test
    @DisplayName("엑세스 토큰 생성 테스트")
    void testCreateAccessToken() {
        Long id = 1L;
        String userName = "testUser";  // userName 추가
        Role role = Role.ADMIN;

        String token = jwtTokenProvider.createAccessToken(id, userName, role);  // userName 추가

        // 토큰이 정상적으로 생성되었는지 확인 (길이 체크)
        assertNotNull(token);
        assertFalse(token.isEmpty());

        // 토큰이 유효한지 검증 (단순 체크)
        assertTrue(jwtTokenProvider.validateAccessToken(token));
    }

    @Test
    @DisplayName("리프레시 토큰 생성")
    void createRefreshToken() {
        Long id = 1L;

        String token = jwtTokenProvider.createRefreshToken(id);

        assertNotNull(token);
        assertFalse(token.isEmpty());

        assertTrue(jwtTokenProvider.validateRefreshToken(token));
    }

    @Test
    @DisplayName("엑세스 토큰 권한 입증 테스트")
    void testGetAuthentication() {
        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN);

        Authentication authentication = jwtTokenProvider.getAuthentication(token);

        // UsernamePasswordAuthenticationToken이 제대로 생성되었는지 확인
        assertNotNull(authentication);
        assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);
        assertEquals("", authentication.getCredentials());  // 빈 비밀번호
    }

    @Test
    @DisplayName("엑세스 토큰 사용자명 추출 테스트")
    void testGetUsername() {
        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN);

        String username = jwtTokenProvider.getUsername(token);

        // 토큰에서 사용자명이 제대로 추출되었는지 확인
        assertNotNull(username);
        assertEquals("testUser", username);  // JWT에서 Subject는 userName으로 설정되었으므로
    }

    @Test
    @DisplayName("엑세스 토큰 ID 추출 테스트")
    void testGetId() {
        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN);

        Long id = jwtTokenProvider.getId(token);

        assertNotNull(id);
        assertEquals(1L, id);
    }

    @Test
    @DisplayName("엑세스 토큰 Role(권한) 추출 테스트")
    void testGetRole() {
        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN);

        String role = jwtTokenProvider.getRole(token);

        assertNotNull(role);
        assertEquals("ADMIN", role);
    }

    @Test
    @DisplayName("유효한 엑세스 토큰 테스트")
    void testValidateToken_ValidToken() {
        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN);

        // 유효한 토큰을 넣었을 때 true가 반환되는지 확인
        assertTrue(jwtTokenProvider.validateAccessToken(token));
    }

    @Test
    @DisplayName("잘못된 엑세스 토큰 테스트")
    void testValidateToken_InvalidToken() {
        // 잘못된 토큰을 넣었을 때 false가 반환되는지 확인
        String invalidToken = "invalidToken";
        assertFalse(jwtTokenProvider.validateAccessToken(invalidToken));
    }

    @Test
    @DisplayName("만료된 엑세스 토큰 테스트")
    void testValidateToken_ExpiredToken() {
        // 만료된 토큰을 테스트할 수 있게끔 만료 시간을 조작
        String expiredToken = createExpiredToken();

        // 만료된 토큰을 넣었을 때 false가 반환되는지 확인
        assertFalse(jwtTokenProvider.validateAccessToken(expiredToken));
    }

    /**
     * 만료된 토큰을 반환
     * @return 기한이 만료된 토큰
     */
    private String createExpiredToken() {
        long expiredValidity = -1000L; // 현재 시간보다 이전으로 만료 설정
        String secret = "secretFEFDSXXXXXXDFFNMKLOPOHHkeyfkadsjkfjdslkfjladsjflak";

        JwtTokenProvider expiredTokenProvider = new JwtTokenProvider(mockRedisTemplate) {

            @Override
            public String createAccessToken(Long id, String userName, Role role) {
                Map<String, Object> claims = new HashMap<>();
                claims.put("role", role);
                claims.put("userName", userName);
                claims.put("id", id);
                claims.put("tokenType", Token.ACCESS_TOKEN);

                Date now = new Date();
                Date exp = new Date(now.getTime() + expiredValidity); // 만료 시간 설정

                return Jwts.builder()
                        .setClaims(claims)
                        .setIssuedAt(now)
                        .setExpiration(exp)
                        .signWith(SignatureAlgorithm.HS256, secret)
                        .compact();
            }
        };
        return expiredTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN);  // userName 추가
    }
}
