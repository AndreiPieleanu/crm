package com.innernetwork.crm.auth;

import java.time.Duration;
import java.util.UUID;

import com.innernetwork.crm.auth.AuthDtos.LoginRequest;
import com.innernetwork.crm.auth.AuthDtos.MeResponse;
import com.innernetwork.crm.auth.AuthDtos.SignupRequest;
import com.innernetwork.crm.auth.AuthDtos.TokenResponse;
import com.innernetwork.crm.auth.AuthService.IssuedTokens;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Login, signup and session endpoints.
 *
 * <p>The access token is returned in the body; the frontend keeps it in memory only. The refresh
 * token is set as an HttpOnly cookie, so JavaScript (and therefore an XSS attack) cannot read it.
 */
@RestController
@RequestMapping("/api")
class AuthController {

	static final String REFRESH_COOKIE = "crm_refresh";

	private static final String REFRESH_COOKIE_PATH = "/api/auth";

	private final AuthService authService;

	AuthController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/auth/signup")
	ResponseEntity<TokenResponse> signup(@Valid @RequestBody SignupRequest request, HttpServletRequest http) {
		return withTokens(HttpStatus.CREATED, this.authService.signup(request, http.getRemoteAddr()));
	}

	@PostMapping("/auth/login")
	ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
		return withTokens(HttpStatus.OK, this.authService.login(request, http.getRemoteAddr()));
	}

	@PostMapping("/auth/refresh")
	ResponseEntity<TokenResponse> refresh(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken) {
		return withTokens(HttpStatus.OK, this.authService.refresh(refreshToken));
	}

	@PostMapping("/auth/logout")
	ResponseEntity<Void> logout(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken) {
		this.authService.logout(refreshToken);
		ResponseCookie cleared = refreshCookie("", Duration.ZERO);
		return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cleared.toString()).build();
	}

	@GetMapping("/me")
	MeResponse me(@AuthenticationPrincipal Jwt jwt) {
		return this.authService.me(UUID.fromString(jwt.getSubject()));
	}

	private static ResponseEntity<TokenResponse> withTokens(HttpStatus status, IssuedTokens tokens) {
		ResponseCookie cookie = refreshCookie(tokens.refreshToken(), tokens.refreshTokenTtl());
		TokenResponse body = new TokenResponse(tokens.accessToken(), "Bearer", tokens.accessTokenTtl().toSeconds());
		return ResponseEntity.status(status).header(HttpHeaders.SET_COOKIE, cookie.toString()).body(body);
	}

	private static ResponseCookie refreshCookie(String value, Duration maxAge) {
		return ResponseCookie.from(REFRESH_COOKIE, value)
			.httpOnly(true)
			.secure(true)
			.sameSite("Strict")
			.path(REFRESH_COOKIE_PATH)
			.maxAge(maxAge)
			.build();
	}

}
