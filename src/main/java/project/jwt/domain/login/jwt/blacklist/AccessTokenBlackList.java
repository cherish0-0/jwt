package project.jwt.domain.login.jwt.blacklist;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class AccessTokenBlackList {

	private final RedisTemplate<String, Object> redisBlackListTemplate;

	@Value("${jwt.seconds-to-add}")
	private Duration accessTokenTimeout;

	public void setBlackList(String key, Object o) {
		redisBlackListTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(o.getClass()));
		redisBlackListTemplate.opsForValue().set(key, o, accessTokenTimeout);
	}

	public boolean isTokenBlackList(String key) {
		return (redisBlackListTemplate.hasKey(key));
	}
}
