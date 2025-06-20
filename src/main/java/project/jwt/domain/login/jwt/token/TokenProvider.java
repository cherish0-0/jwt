package project.jwt.domain.login.jwt.token;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import project.jwt.domain.login.dto.TokenInfo;
import project.jwt.domain.login.dto.TokenValidationResult;
import project.jwt.domain.member.Member;

import java.security.Key;
import java.time.Duration;
import java.util.Date;
import java.util.UUID;

@Slf4j
public class TokenProvider {

    private static final String AUTHORITIES_KEY = "auth";
    private static final String TOKEN_ID_KEY = "tokenId";
    private static final String USERNAME_KEY = "username";

    private final Key hashKey;
    private final long accessTokenValidationInSeconds;

    public TokenProvider (String secrete, long accessTokenValidationInSeconds) {
        byte[] keyBytes = Decoders.BASE64.decode(secrete);
        this.hashKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenValidationInSeconds = accessTokenValidationInSeconds * 1000;
    }

    public TokenInfo createToken(Member member) {
        long currentTime = (new Date()).getTime();
        Date accessTokenExpireTime = new Date(currentTime + accessTokenValidationInSeconds);
        String tokenId = UUID.randomUUID().toString();

        /**
         * JWT 토큰 생성
         * - setSubject: 토큰 페이로드(속성)의 주체 설정
         * - claim: 페이로드의 속성 설정 (키, 값 쌍으로 저장)
         * - compact: JWT 토큰 문자열로 변환
         */
        String accessToken = Jwts.builder()
                .setSubject(member.getEmail())
                .claim(AUTHORITIES_KEY, member.getRole())
                .claim(USERNAME_KEY, member.getUsername())
                .claim(TOKEN_ID_KEY, tokenId)
                .signWith(hashKey, SignatureAlgorithm.HS512)
                .setIssuedAt(new Date(currentTime))
                .setExpiration(accessTokenExpireTime)
                .compact();

        return TokenInfo.builder()
                .ownerEmail(member.getEmail())
                .tokenId(tokenId)
                .accessToken(accessToken)
                .accessTokenExpireTime(accessTokenExpireTime)
                .build();
    }

    public TokenValidationResult validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(hashKey).build().parseClaimsJws(token).getBody();
            return new TokenValidationResult(TokenStatus.TOKEN_VALID, TokenType.ACCESS,
                    claims.get(TOKEN_ID_KEY, String.class), claims);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰");
            Claims claims = e.getClaims();
            log.error("issue: {}, expiration: {}", claims.getIssuedAt(), claims.getExpiration());
            return new TokenValidationResult(TokenStatus.TOKEN_EXPIRED, TokenType.ACCESS, claims.get(TOKEN_ID_KEY, String.class), null);
        } catch (SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명");
            return new TokenValidationResult(TokenStatus.TOKEN_WRONG_SIGNATURE, null, null, null);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 서명");
            return new TokenValidationResult(TokenStatus.TOKEN_HASH_NOT_SUPPORTED, null, null, null);
        } catch (IllegalArgumentException e) {
            log.info("잘못된 JWT 토큰");
            return new TokenValidationResult(TokenStatus.TOKEN_WRONG_SIGNATURE, null, null, null);
        }
    }
}
