package project.jwt.domain.login.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import project.jwt.domain.login.dto.TokenValidationResult;
import project.jwt.domain.login.jwt.token.TokenStatus;
import project.jwt.web.controller.json.ApiResponseJson;
import project.jwt.web.controller.json.ResponseStatusCode;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private static final String VALIDATION_RESULT_KEY = "result";
	private static final String ERROR_MESSAGE_KEY = "errMsg";
	private static final ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException authException) throws IOException, ServletException {
		TokenValidationResult result = (TokenValidationResult)request.getAttribute(VALIDATION_RESULT_KEY);
		String errorMessage = result.getTokenStatus().getMessage();
		int errorCode;

		switch (result.getTokenStatus()) {
			case TOKEN_EXPIRED -> errorCode = ResponseStatusCode.TOKEN_EXPIRED;
			case TOKEN_IS_BLACKLIST -> errorCode = ResponseStatusCode.TOKEN_IS_BLACKLIST;
			case TOKEN_WRONG_SIGNATURE -> errorCode = ResponseStatusCode.TOKEN_WRONG_SIGNATURE;
			case TOKEN_HASH_NOT_SUPPORTED -> errorCode = ResponseStatusCode.TOKEN_HASH_NOT_SUPPORTED;
			case WRONG_AUTH_HEADER -> errorCode = ResponseStatusCode.NO_AUTH_HEADER;
			default -> {
				errorMessage = TokenStatus.TOKEN_VALIDATION_TRY_FAILED.getMessage();
				errorCode = ResponseStatusCode.TOKEN_VALIDATION_TRY_FAILED;
			}
		}

		sendError(response, errorMessage, errorCode);

	}

	private void sendError(HttpServletResponse response, String msg, int code) throws IOException {
		final int ERROR_401 = HttpServletResponse.SC_UNAUTHORIZED;

		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.setStatus(ERROR_401);

		ApiResponseJson responseJson = new ApiResponseJson(
			HttpStatus.valueOf(ERROR_401),
			code, Map.of(ERROR_MESSAGE_KEY, msg));

		String jsonToString = objectMapper.writeValueAsString(responseJson);
		response.getWriter().write(jsonToString);
	}
}