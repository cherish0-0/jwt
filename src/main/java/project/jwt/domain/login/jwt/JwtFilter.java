package project.jwt.domain.login.jwt;

import java.io.IOException;
import java.util.regex.Pattern;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import project.jwt.domain.login.dto.TokenValidationResult;
import project.jwt.domain.login.jwt.token.TokenProvider;
import project.jwt.domain.login.jwt.token.TokenStatus;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String BEARER_PREFIX = "Bearer ([a-zA-Z0-9_\\-\\+\\/=]+)\\.([a-zA-Z0-9_\\-\\+\\/=]+)\\.([a-zA-Z0-9_.\\-\\+\\/=]*)";
	private static final Pattern BEARER_PATTERN = Pattern.compile(BEARER_PREFIX);
	private final TokenProvider tokenProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		String token = resolveToken(request);

		if (!StringUtils.hasText(token)) {
			handleMissingToken(request, response, filterChain);
			return;
		}

		TokenValidationResult tokenValidationResult = tokenProvider.validateToken(token);
		if (!tokenValidationResult.isValid()) {
			handleWrongToken(request, response, filterChain, tokenValidationResult);
		}

		handleValidToken(token, tokenValidationResult);
		filterChain.doFilter(request, response);
	}

	private void handleValidToken(String token, TokenValidationResult tokenValidationResult) {
		Authentication authentication = tokenProvider.getAuthentication(token, tokenValidationResult.getClaims());
		SecurityContextHolder.getContext().setAuthentication(authentication);
		log.info("AUTH SUCCESS: {}", authentication.getName());
	}

	private static void handleWrongToken(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain,
		TokenValidationResult tokenValidationResult) throws IOException, ServletException {
		request.setAttribute("result", tokenValidationResult);
		filterChain.doFilter(request, response);
	}

	private static void handleMissingToken(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws IOException, ServletException {
		request.setAttribute("result", new TokenValidationResult(TokenStatus.WRONG_AUTH_HEADER, null, null, null));
		filterChain.doFilter(request, response);
	}

	private String resolveToken(HttpServletRequest request) {
		String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
		if (bearerToken != null && BEARER_PATTERN.matcher(bearerToken).matches()) {
			return bearerToken.substring(7); // "Bearer " 이후의 토큰 부분을 반환
		}

		return null;
	}
}
