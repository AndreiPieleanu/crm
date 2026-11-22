package com.innernetwork.crm;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthSecurityTest extends IntegrationTest {

	@Test
	void apiRequiresAToken() throws Exception {
		this.mvc.perform(get("/api/contacts")).andExpect(status().isUnauthorized());
		this.mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
		this.mvc.perform(get("/api/anything-new")).andExpect(status().isUnauthorized());
	}

	@Test
	void tokenSignedWithAnotherKeyIsRejected() throws Exception {
		Account alpha = signup("Alpha SRL");
		byte[] otherKey = "a-completely-different-secret-key-32b!".getBytes();
		NimbusJwtEncoder forger = new NimbusJwtEncoder(new ImmutableSecret<>(new SecretKeySpec(otherKey, "HmacSHA256")));
		String forged = forger.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),
				JwtClaimsSet.builder()
					.issuer("crm-backend")
					.subject(UUID.randomUUID().toString())
					.issuedAt(Instant.now())
					.expiresAt(Instant.now().plusSeconds(600))
					.claim("tid", alpha.tenantId().toString())
					.claim("roles", List.of("ADMIN"))
					.build()))
			.getTokenValue();

		this.mvc.perform(get("/api/contacts").header("Authorization", "Bearer " + forged))
			.andExpect(status().isUnauthorized());
		this.mvc.perform(get("/api/contacts").header("Authorization", "Bearer " + alpha.accessToken() + "x"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void refreshCookieIsHttpOnlySecureAndStrict() throws Exception {
		MvcResult result = this.mvc.perform(post("/api/auth/signup")
			.contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"companyName": "Gamma SRL", "fullName": "Ion Pop",
					 "email": "ion-%s@example.ro", "password": "a long enough password"}
					""".formatted(UUID.randomUUID())))
			.andExpect(status().isCreated())
			.andReturn();

		String setCookie = result.getResponse().getHeader("Set-Cookie");
		assertThat(setCookie).contains("crm_refresh=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/api/auth");
		assertThat(result.getResponse().getContentAsString()).doesNotContain("password");
	}

	@Test
	void wrongPasswordAndUnknownEmailGiveTheSameAnswer() throws Exception {
		Account alpha = signup("Alpha SRL");

		String wrongPassword = this.mvc.perform(post("/api/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\": \"%s\", \"password\": \"not the password\"}".formatted(alpha.email())))
			.andExpect(status().isUnauthorized())
			.andReturn().getResponse().getContentAsString();
		String unknownEmail = this.mvc.perform(post("/api/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\": \"nobody-%s@example.ro\", \"password\": \"whatever pass\"}".formatted(UUID.randomUUID())))
			.andExpect(status().isUnauthorized())
			.andReturn().getResponse().getContentAsString();

		assertThat(wrongPassword).isEqualTo(unknownEmail);
	}

	@Test
	void repeatedFailedLoginsAreBlockedEvenWithTheRightPassword() throws Exception {
		Account alpha = signup("Alpha SRL");
		for (int i = 0; i < 5; i++) {
			this.mvc.perform(post("/api/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"email\": \"%s\", \"password\": \"guess number %d\"}".formatted(alpha.email(), i)))
				.andExpect(status().isUnauthorized());
		}

		this.mvc.perform(post("/api/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(alpha.email(), alpha.password())))
			.andExpect(status().isTooManyRequests())
			.andExpect(header().exists("Retry-After"));
	}

	@Test
	void refreshTokenWorksOnceAndReuseEndsAllSessions() throws Exception {
		Account alpha = signup("Alpha SRL");

		MvcResult first = this.mvc.perform(post("/api/auth/refresh").cookie(new Cookie("crm_refresh", alpha.refreshCookie())))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.accessToken").isNotEmpty())
			.andReturn();
		String rotated = first.getResponse().getCookie("crm_refresh").getValue();
		assertThat(rotated).isNotEqualTo(alpha.refreshCookie());

		// The old token is used again: treated as stolen.
		this.mvc.perform(post("/api/auth/refresh").cookie(new Cookie("crm_refresh", alpha.refreshCookie())))
			.andExpect(status().isUnauthorized());
		// ...so the new one stops working too.
		this.mvc.perform(post("/api/auth/refresh").cookie(new Cookie("crm_refresh", rotated)))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void logoutRevokesTheRefreshToken() throws Exception {
		Account alpha = signup("Alpha SRL");

		this.mvc.perform(post("/api/auth/logout").cookie(new Cookie("crm_refresh", alpha.refreshCookie())))
			.andExpect(status().isNoContent())
			.andExpect(header().string("Set-Cookie", containsString("Max-Age=0")));
		this.mvc.perform(post("/api/auth/refresh").cookie(new Cookie("crm_refresh", alpha.refreshCookie())))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void signupValidatesInputAndDoesNotRevealDuplicates() throws Exception {
		this.mvc.perform(post("/api/auth/signup")
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"companyName\": \"X\", \"fullName\": \"Y\", \"email\": \"not-an-email\", \"password\": \"short\"}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors[*].field", org.hamcrest.Matchers.containsInAnyOrder("email", "password")));

		Account alpha = signup("Alpha SRL");
		this.mvc.perform(post("/api/auth/signup")
			.contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"companyName": "Copy SRL", "fullName": "Ana Pop",
					 "email": "%s", "password": "another long password"}
					""".formatted(alpha.email().toUpperCase())))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.detail").value("An account cannot be created with these details."));
	}

	@Test
	void responsesCarrySecurityHeadersAndNoInternals() throws Exception {
		Account alpha = signup("Alpha SRL");

		this.mvc.perform(get("/api/contacts").header("Authorization", alpha.bearer()))
			.andExpect(header().string("X-Content-Type-Options", "nosniff"))
			.andExpect(header().string("X-Frame-Options", "DENY"))
			.andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
			.andExpect(header().string("Cache-Control", containsString("no-store")));

		this.mvc.perform(get("/api/contacts/not-a-uuid").header("Authorization", alpha.bearer()))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.trace").doesNotExist())
			.andExpect(jsonPath("$.exception").doesNotExist());
	}

	@Test
	void healthIsPublicButOtherActuatorEndpointsAreNot() throws Exception {
		this.mvc.perform(get("/actuator/health")).andExpect(status().isOk());
		this.mvc.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
	}

}
