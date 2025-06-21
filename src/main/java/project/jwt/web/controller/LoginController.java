package project.jwt.web.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import project.jwt.domain.login.LoginService;
import project.jwt.domain.login.dto.TokenInfo;
import project.jwt.domain.member.Member;
import project.jwt.domain.member.UserPrinciple;
import project.jwt.web.controller.dto.MemberCreateDto;
import project.jwt.web.controller.dto.MemberLoginDto;
import project.jwt.web.controller.json.ApiResponseJson;

@Slf4j
@RestController
@RequiredArgsConstructor
public class LoginController {
	private final LoginService loginService;

	@PostMapping("/api/account/create")
	public ApiResponseJson createNewAccount(@Valid @RequestBody MemberCreateDto memberCreateDto,
		BindingResult bindingResult) {
		if (bindingResult.hasErrors()) {
			log.info("회원가입 실패: {}", bindingResult.getAllErrors());
			throw new IllegalArgumentException("잘못된 요청입니다.");
		}

		Member member = loginService.createMember(memberCreateDto);
		log.info("회원가입 성공: {}", member.getEmail());

		return new ApiResponseJson(HttpStatus.OK, Map.of(
			"email", member.getEmail(),
			"username", member.getUsername()
		));
	}

	@PostMapping("/api/account/auth")
	public ApiResponseJson authenticateAccountAndIssueToken(@Valid @RequestBody MemberLoginDto memberLoginDto,
		BindingResult bindingResult) {
		if (bindingResult.hasErrors()) {
			log.info("로그인 실패: {}", bindingResult.getAllErrors());
			throw new IllegalArgumentException("잘못된 요청입니다.");
		}

		TokenInfo tokenInfo = loginService.loginMember(memberLoginDto.getEmail(), memberLoginDto.getPassword());
		log.info("Token 발급 성공: {}", tokenInfo);

		return new ApiResponseJson(HttpStatus.OK, tokenInfo);
	}

	@GetMapping("/api/account/userinfo")
	public ApiResponseJson getUserInfo(@AuthenticationPrincipal UserPrinciple userPrinciple) {
		log.info("요청 이메일 : {}", userPrinciple.getEmail());

		Member foundMember = loginService.getUserInfo(userPrinciple.getEmail());

		return new ApiResponseJson(HttpStatus.OK, foundMember);
	}

	@PostMapping("/api/account/logout")
	public ApiResponseJson logout(@AuthenticationPrincipal UserPrinciple userPrinciple,
		@RequestHeader("Authorization") String authHeader) {
		log.info("로그아웃 요청 이메일: {}", userPrinciple.getEmail());
		loginService.logout(authHeader.substring(7), userPrinciple.getEmail());

		return new ApiResponseJson(HttpStatus.OK, "로그아웃이 완료되었습니다. BYE!");
	}
}
