package com.innernetwork.crm.config;

import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.innernetwork.crm.tenancy.TenantContext;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Access tokens are JWTs signed with HMAC-SHA256 using a secret key from the environment.
 * Only HS256 is accepted, so a token cannot choose a weaker algorithm ("alg" confusion).
 */
@Configuration(proxyBeanMethods = false)
class JwtConfig {

	private static final int MIN_KEY_BYTES = 32;

	@Bean
	SecretKey jwtSigningKey(CrmProperties properties) {
		String secret = properties.jwt().secret();
		if (secret.contains("${")) {
			throw new IllegalStateException("CRM_JWT_SECRET is not set");
		}
		byte[] keyBytes;
		try {
			keyBytes = Base64.getDecoder().decode(secret.trim());
		}
		catch (IllegalArgumentException ex) {
			throw new IllegalStateException("CRM_JWT_SECRET must be base64-encoded", ex);
		}
		if (keyBytes.length < MIN_KEY_BYTES) {
			throw new IllegalStateException("CRM_JWT_SECRET must decode to at least " + MIN_KEY_BYTES + " bytes");
		}
		return new SecretKeySpec(keyBytes, "HmacSHA256");
	}

	@Bean
	JwtEncoder jwtEncoder(SecretKey jwtSigningKey) {
		return new NimbusJwtEncoder(new ImmutableSecret<>(jwtSigningKey));
	}

	@Bean
	JwtDecoder jwtDecoder(SecretKey jwtSigningKey, CrmProperties properties) {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSigningKey)
			.macAlgorithm(MacAlgorithm.HS256)
			.build();
		decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<Jwt>(
				JwtValidators.createDefaultWithIssuer(properties.jwt().issuer()),
				new JwtClaimValidator<String>(TenantContext.TENANT_CLAIM, Objects::nonNull),
				new JwtClaimValidator<String>("sub", Objects::nonNull)));
		return decoder;
	}

}
