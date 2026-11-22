package com.innernetwork.crm.config;

import java.time.Duration;
import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Application settings under the {@code crm.*} prefix. Checked at startup: bad values stop the app. */
@Validated
@ConfigurationProperties("crm")
public record CrmProperties(
		@Valid @NotNull Jwt jwt,
		@Valid @NotNull Cors cors,
		@Valid @NotNull LoginRateLimit loginRateLimit) {

	public record Jwt(
			@NotBlank String secret,
			@NotBlank String issuer,
			@NotNull Duration accessTokenTtl,
			@NotNull Duration refreshTokenTtl) {
	}

	public record Cors(@NotEmpty List<String> allowedOrigins) {
	}

	public record LoginRateLimit(
			@Positive int maxFailuresPerAccount,
			@Positive int maxFailuresPerIp,
			@NotNull Duration window) {
	}

}
