package com.innernetwork.crm.auth;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Database access for refresh tokens. Only SHA-256 hashes are stored. */
@Repository
class RefreshTokens {

	record TokenRow(UUID id, UUID tenantId, UUID userId, OffsetDateTime expiresAt, OffsetDateTime revokedAt) {
	}

	private final JdbcClient jdbc;

	RefreshTokens(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	void insert(UUID userId, byte[] tokenHash, OffsetDateTime expiresAt) {
		this.jdbc.sql("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (:userId, :hash, :expiresAt)")
			.param("userId", userId)
			.param("hash", tokenHash)
			.param("expiresAt", expiresAt)
			.update();
	}

	/** Looks up a token before the tenant is known, through a narrow SECURITY DEFINER function. */
	Optional<TokenRow> findByHash(byte[] tokenHash) {
		return this.jdbc.sql("SELECT * FROM auth_find_refresh_token(:hash)")
			.param("hash", tokenHash)
			.query(TokenRow.class)
			.optional();
	}

	/** Returns true only for the one caller that revoked a still-active token. */
	boolean revokeIfActive(UUID tokenId) {
		return this.jdbc.sql("UPDATE refresh_tokens SET revoked_at = now() WHERE id = :id AND revoked_at IS NULL")
			.param("id", tokenId)
			.update() == 1;
	}

	void revokeAllForUser(UUID userId) {
		this.jdbc.sql("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = :userId AND revoked_at IS NULL")
			.param("userId", userId)
			.update();
	}

}
