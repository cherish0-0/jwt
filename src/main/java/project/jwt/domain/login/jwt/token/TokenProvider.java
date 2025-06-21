package project.jwt.domain.login.jwt.token;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import project.jwt.domain.login.dto.TokenInfo;
import project.jwt.domain.login.dto.TokenValidationResult;
import project.jwt.domain.member.Member;
import project.jwt.domain.member.UserPrinciple;

import java.security.Key;
import java.time.*;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Slf4j
public class TokenProvider {

	private static final String AUTHORITIES_KEY = "auth";
	private static final String TOKEN_ID_KEY = "tokenId";
	private static final String USERNAME_KEY = "username";

	private final Key hashKey;
	private final Duration secondsToAdd;

	public TokenProvider(String secrete, Duration secondsToAdd) {
		byte[] keyBytes = Decoders.BASE64.decode(secrete);
		this.hashKey = Keys.hmacShaKeyFor(keyBytes);
		this.secondsToAdd = secondsToAdd;
	}

	/**
	 * JWT 토큰 생성
	 * - setSubject: 토큰 페이로드(속성)의 주체 설정
	 * - claim: 페이로드의 속성 설정 (키, 값 쌍으로 저장)
	 * - compact: JWT 토큰 문자열로 변환
	 */
	public TokenInfo createToken(Member member) {
		String tokenId = UUID.randomUUID().toString();
		Date issuedAt = Date.from(Instant.now());
		Date expiration = Date.from(issuedAt.toInstant().plus(this.secondsToAdd));

		String accessToken = Jwts.builder()
			.setSubject(member.getEmail())
			.claim(AUTHORITIES_KEY, member.getRole())
			.claim(USERNAME_KEY, member.getUsername())
			.claim(TOKEN_ID_KEY, tokenId)
			.signWith(hashKey, SignatureAlgorithm.HS512)
			.setIssuedAt(issuedAt)
			.setExpiration(expiration)
			.compact();

		return TokenInfo.builder()
			.ownerEmail(member.getEmail())
			.tokenId(tokenId)
			.accessToken(accessToken)
			.accessTokenExpireTime(expiration)
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
			return new TokenValidationResult(TokenStatus.TOKEN_EXPIRED, TokenType.ACCESS,
				claims.get(TOKEN_ID_KEY, String.class), null);
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

	public Authentication getAuthentication(String token, Claims claims) {
		List<? extends GrantedAuthority> authorities = Arrays.stream(
				claims.get(AUTHORITIES_KEY).toString().split(","))
			.map(SimpleGrantedAuthority::new)
			.toList();

		UserPrinciple principle = new UserPrinciple(claims.getSubject(), claims.get(USERNAME_KEY, String.class),
			authorities);
		return new UsernamePasswordAuthenticationToken(principle, token, authorities);
	}
}
