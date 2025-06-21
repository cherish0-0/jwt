package project.jwt.domain.login.jwt.token;

import lombok.extern.slf4j.Slf4j;

import org.junit.jupiter.api.Test;

import project.jwt.domain.login.dto.TokenInfo;
import project.jwt.domain.login.dto.TokenValidationResult;
import project.jwt.domain.member.Member;
import project.jwt.domain.member.Role;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;

@Slf4j
class TokenProviderTest {
	private final String secrete = "dGhpcyBpcyBteSBoaWRkZW4gand0IHNlY3JldGUga2V5LCB3aGF0IGlzIHlvdXIgand0IHNlY3JldGUga2V5Pw==";
	private final Duration secondsToAdd = Duration.of(3, ChronoUnit.SECONDS); // 3초
	private final TokenProvider tokenProvider = new TokenProvider(secrete, secondsToAdd);

	@Test
	void createToken() {
		Member member = getMember();

		TokenInfo token = tokenProvider.createToken(member);
		String accessToken = token.getAccessToken();

		TokenValidationResult result = tokenProvider.validateToken(accessToken);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	void validationTokenValid() {
		Member member = getMember();
		TokenInfo token = tokenProvider.createToken(member);
		String accessToken = token.getAccessToken();

		TokenValidationResult result = tokenProvider.validateToken(accessToken);

		assertThat(result.isValid()).isTrue();
		log.info(Date.from(Instant.now()).toString());
		log.info(token.getAccessTokenExpireTime().toString());
	}

	private Member getMember() {
		return Member.builder()
			.email("studying@naver.com")
			.password("1234")
			.username("dev")
			.role(Role.ROLE_USER)
			.build();
	}
}