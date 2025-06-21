package project.jwt.domain.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import project.jwt.domain.login.jwt.JwtAccessDeniedHandler;
import project.jwt.domain.login.jwt.JwtAuthenticationEntryPoint;
import project.jwt.domain.login.jwt.JwtProperties;
import project.jwt.domain.login.jwt.blacklist.AccessTokenBlackList;
import project.jwt.domain.login.jwt.token.TokenProvider;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {

	private final AccessTokenBlackList accessTokenBlackList;

	@Bean
	public TokenProvider tokenProvider(JwtProperties jwtProperties) {
		return new TokenProvider(jwtProperties.getSecret(), jwtProperties.getSecondsToAdd(), accessTokenBlackList);
	}

	@Bean
	public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
		return new JwtAuthenticationEntryPoint();
	}

	@Bean
	public JwtAccessDeniedHandler jwtAccessDeniedHandler() {
		return new JwtAccessDeniedHandler();
	}
}
