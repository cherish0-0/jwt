package project.jwt.web.filter;

import static org.springframework.http.HttpStatus.*;

import java.io.IOException;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 1)
public class ExceptionFilter extends OncePerRequestFilter {

	private static final String INTERNAL_SERVER_ERROR = "Unexpected Server Error";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		try {
			doFilter(request, response, filterChain);
		} catch (Exception e) {
			log.error(INTERNAL_SERVER_ERROR, e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR);
		}
	}
}
