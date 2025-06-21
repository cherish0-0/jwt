package project.jwt.domain.login.jwt;

import java.time.Duration;

import lombok.Data;

import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
	private String header;
	private String secret;
	private Duration SecondsToAdd;
}
