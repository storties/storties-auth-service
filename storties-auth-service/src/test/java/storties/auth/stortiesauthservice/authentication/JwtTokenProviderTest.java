//package storties.auth.stortiesauthservice.authentication;
//
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.data.redis.core.ValueOperations;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import storties.auth.stortiesauthservice.persistence.type.Role;
//
//import java.util.Map;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.Mockito.*;
//
//class JwtTokenProviderTest {
//
//    private RedisTemplate<String, String> mockRedisTemplate;
//    private ValueOperations<String, String> mockValueOperations;
//    private JwtTokenProvider jwtTokenProvider;
//
//    @BeforeEach
//    void setUp() {
//        mockRedisTemplate = mock(RedisTemplate.class);
//        mockValueOperations = mock(ValueOperations.class);
//
//        when(mockRedisTemplate.opsForValue()).thenReturn(mockValueOperations);
//
//        //jwtTokenProvider = new JwtTokenProvider(mockRedisTemplate);
//    }
//
//    @Test
//    @DisplayName("엑세스 토큰 생성 테스트")
//    void testCreateAccessToken() {
//        Long id = 1L;
//        String userName = "testUser";
//        Role role = Role.ADMIN;
//
//        Map<String, Object> response = jwtTokenProvider.createAccessToken(id, userName, role);
//
//        // 토큰 생성 확인
//        String token = (String) response.get("token");
//        assertNotNull(token);
//        assertFalse(token.isEmpty());
//
//        // 만료 시간 확인
//        assertNotNull(response.get("expiresIn"));
//        assertNotNull(response.get("expiresAt"));
//
//        // 토큰 유효성 검증
//        assertTrue(jwtTokenProvider.validateAccessToken(token));
//    }
//
//    @Test
//    @DisplayName("리프레시 토큰 생성")
//    void createRefreshToken() {
//        Long id = 1L;
//
//        Map<String, Object> response = jwtTokenProvider.createRefreshToken(id);
//
//        // 리프레시 토큰 생성 확인
//        String token = (String) response.get("token");
//        assertNotNull(token);
//        assertFalse(token.isEmpty());
//
//        // 만료 시간 확인
//        assertNotNull(response.get("expiresIn"));
//        assertNotNull(response.get("expiresAt"));
//
//        // 토큰 유효성 검증
//        assertTrue(jwtTokenProvider.validateRefreshToken(token));
//    }
//
//    @Test
//    @DisplayName("엑세스 토큰 권한 입증 테스트")
//    void testGetAuthentication() {
//        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN).get("token").toString();
//
//        Authentication authentication = jwtTokenProvider.getAuthentication(token);
//
//        // UsernamePasswordAuthenticationToken이 제대로 생성되었는지 확인
//        assertNotNull(authentication);
//        assertTrue(authentication instanceof UsernamePasswordAuthenticationToken);
//        assertEquals("", authentication.getCredentials());  // 빈 비밀번호
//    }
//
//    @Test
//    @DisplayName("엑세스 토큰 사용자명 추출 테스트")
//    void testGetUsername() {
//        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN).get("token").toString();
//
//        String username = jwtTokenProvider.getEmailByAccessToken(token);
//
//        // 토큰에서 사용자명이 제대로 추출되었는지 확인
//        assertNotNull(username);
//        assertEquals("testUser", username);  // JWT에서 Subject는 userName으로 설정되었으므로
//    }
//
//    @Test
//    @DisplayName("엑세스 토큰 ID 추출 테스트")
//    void testGetId() {
//        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN).get("token").toString();
//
//        Long id = jwtTokenProvider.getId(token);
//
//        assertNotNull(id);
//        assertEquals(1L, id);
//    }
//
//    @Test
//    @DisplayName("엑세스 토큰 Role(권한) 추출 테스트")
//    void testGetRole() {
//        String token = jwtTokenProvider.createAccessToken(1L, "testUser", Role.ADMIN).get("token").toString();
//
//        String role = jwtTokenProvider.getRoleByAccessToken(token);
//
//        assertNotNull(role);
//        assertEquals("ADMIN", role);
//    }
//}
