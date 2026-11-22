package com.innernetwork.crm.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.innernetwork.crm.config.CrmProperties;
import com.innernetwork.crm.tenancy.TenantContext;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/** Creates short-lived access tokens (JWT) that carry the user, the tenant and the role. */
@Service
class AccessTokenService {

	private final JwtEncoder encoder;

	private final String issuer;

	private final Duration ttl;

	AccessTokenService(JwtEncoder encoder, CrmProperties properties) {
		this.encoder = encoder;
		this.issuer = properties.jwt().issuer();
		this.ttl = properties.jwt().accessTokenTtl();
	}

	String create(UUID userId, UUID tenantId, String role) {
		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder()
			.issuer(this.issuer)
			.subject(userId.toString())
			.issuedAt(now)
			.expiresAt(now.plus(this.ttl))
			.id(UUID.randomUUID().toString())
			.claim(TenantContext.TENANT_CLAIM, tenantId.toString())
			.claim("roles", List.of(role))
			.build();
		JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
		return this.encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

	Duration ttl() {
		return this.ttl;
	}

}
