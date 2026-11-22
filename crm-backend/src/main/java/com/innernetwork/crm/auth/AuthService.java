package com.innernetwork.crm.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.innernetwork.crm.auth.AuthDtos.LoginRequest;
import com.innernetwork.crm.auth.AuthDtos.MeResponse;
import com.innernetwork.crm.auth.AuthDtos.SignupRequest;
import com.innernetwork.crm.auth.AuthExceptions.AccountUnavailableException;
import com.innernetwork.crm.auth.AuthExceptions.InvalidCredentialsException;
import com.innernetwork.crm.auth.AuthExceptions.InvalidRefreshTokenException;
import com.innernetwork.crm.auth.RefreshTokens.TokenRow;
import com.innernetwork.crm.auth.UserAccounts.LoginRow;
import com.innernetwork.crm.auth.UserAccounts.UserRow;
import com.innernetwork.crm.config.CrmProperties;
import com.innernetwork.crm.tenancy.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
class AuthService {

	/** Tokens issued at login, signup or refresh. The refresh token goes into an HttpOnly cookie. */
	record IssuedTokens(String accessToken, Duration accessTokenTtl, String refreshToken, Duration refreshTokenTtl) {
	}

	private static final Logger log = LoggerFactory.getLogger(AuthService.class);

	private static final int REFRESH_TOKEN_BYTES = 32;

	private static final int MAX_REFRESH_TOKEN_LENGTH = 100;

	private final SecureRandom random = new SecureRandom();

	private final UserAccounts users;

	private final RefreshTokens refreshTokens;

	private final AccessTokenService accessTokens;

	private final PasswordEncoder passwordEncoder;

	private final LoginRateLimiter rateLimiter;

	private final TransactionTemplate tx;

	private final Duration refreshTokenTtl;

	/** Checked when the e-mail is unknown, so a login takes the same time whether the account exists or not. */
	private final String dummyPasswordHash;

	AuthService(UserAccounts users, RefreshTokens refreshTokens, AccessTokenService accessTokens,
			PasswordEncoder passwordEncoder, LoginRateLimiter rateLimiter, TransactionTemplate tx,
			CrmProperties properties) {
		this.users = users;
		this.refreshTokens = refreshTokens;
		this.accessTokens = accessTokens;
		this.passwordEncoder = passwordEncoder;
		this.rateLimiter = rateLimiter;
		this.tx = tx;
		this.refreshTokenTtl = properties.jwt().refreshTokenTtl();
		this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
	}

	/** Creates a new tenant (company) and its first user, who becomes the tenant's admin. */
	IssuedTokens signup(SignupRequest request, String clientIp) {
		this.rateLimiter.checkAndRecordSignup(clientIp);
		String email = normalizeEmail(request.email());
		String passwordHash = this.passwordEncoder.encode(request.password());
		UUID tenantId = UUID.randomUUID();

		return TenantContext.callAs(tenantId, () -> this.tx.execute(status -> {
			this.users.createTenant(tenantId, request.companyName().strip(), normalizeCui(request.cui()));
			UUID userId;
			try {
				userId = this.users.createUser(email, request.fullName().strip(), passwordHash, "ADMIN");
			}
			catch (DuplicateKeyException ex) {
				throw new AccountUnavailableException();
			}
			return issueTokens(userId, tenantId, "ADMIN");
		}));
	}

	IssuedTokens login(LoginRequest request, String clientIp) {
		String email = normalizeEmail(request.email());
		this.rateLimiter.checkLoginAllowed(clientIp, email);

		Optional<LoginRow> found = this.users.findForLogin(email);
		String hashToCheck = found.map(LoginRow::passwordHash).orElse(this.dummyPasswordHash);
		boolean passwordMatches = this.passwordEncoder.matches(request.password(), hashToCheck);
		if (found.isEmpty() || !passwordMatches || !found.get().enabled()) {
			this.rateLimiter.recordLoginFailure(clientIp, email);
			throw new InvalidCredentialsException();
		}
		this.rateLimiter.recordLoginSuccess(email);

		LoginRow user = found.get();
		return TenantContext.callAs(user.tenantId(), () -> this.tx.execute(status -> {
			if (this.passwordEncoder.upgradeEncoding(user.passwordHash())) {
				this.users.updatePasswordHash(user.id(), this.passwordEncoder.encode(request.password()));
			}
			return issueTokens(user.id(), user.tenantId(), user.role());
		}));
	}

	/**
	 * Exchanges a refresh token for new tokens. Each refresh token works once (rotation). If an
	 * already-used token comes back, it was probably stolen, so all of that user's sessions end.
	 */
	IssuedTokens refresh(String rawRefreshToken) {
		TokenRow token = findToken(rawRefreshToken).orElseThrow(InvalidRefreshTokenException::new);
		return TenantContext.callAs(token.tenantId(), () -> {
			if (token.revokedAt() != null) {
				this.tx.executeWithoutResult(status -> this.refreshTokens.revokeAllForUser(token.userId()));
				log.warn("Reused refresh token detected; all sessions of user {} were revoked", token.userId());
				throw new InvalidRefreshTokenException();
			}
			if (token.expiresAt().isBefore(now())) {
				throw new InvalidRefreshTokenException();
			}
			return this.tx.execute(status -> {
				if (!this.refreshTokens.revokeIfActive(token.id())) {
					throw new InvalidRefreshTokenException();
				}
				UserRow user = this.users.findById(token.userId())
					.filter(UserRow::enabled)
					.orElseThrow(InvalidRefreshTokenException::new);
				return issueTokens(user.id(), user.tenantId(), user.role());
			});
		});
	}

	void logout(String rawRefreshToken) {
		findToken(rawRefreshToken).ifPresent(token -> TenantContext.runAs(token.tenantId(),
				() -> this.refreshTokens.revokeIfActive(token.id())));
	}

	MeResponse me(UUID userId) {
		UserRow user = this.users.findById(userId).orElseThrow(InvalidRefreshTokenException::new);
		return new MeResponse(user.id(), user.tenantId(), user.email(), user.fullName(), user.role(),
				user.companyName());
	}

	private Optional<TokenRow> findToken(String rawRefreshToken) {
		if (rawRefreshToken == null || rawRefreshToken.isBlank() || rawRefreshToken.length() > MAX_REFRESH_TOKEN_LENGTH) {
			return Optional.empty();
		}
		return this.refreshTokens.findByHash(sha256(rawRefreshToken));
	}

	/** Must run inside the tenant of {@code tenantId}. */
	private IssuedTokens issueTokens(UUID userId, UUID tenantId, String role) {
		byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
		this.random.nextBytes(bytes);
		String refreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		this.refreshTokens.insert(userId, sha256(refreshToken), now().plus(this.refreshTokenTtl));
		String accessToken = this.accessTokens.create(userId, tenantId, role);
		return new IssuedTokens(accessToken, this.accessTokens.ttl(), refreshToken, this.refreshTokenTtl);
	}

	private static OffsetDateTime now() {
		return OffsetDateTime.now(ZoneOffset.UTC);
	}

	static String normalizeEmail(String email) {
		return email.strip().toLowerCase(Locale.ROOT);
	}

	/** "RO 12345678" and "12345678" are the same company: stored as digits only. */
	static String normalizeCui(String cui) {
		if (cui == null || cui.isBlank()) {
			return null;
		}
		return cui.replaceAll("(?i)^\\s*RO", "").strip();
	}

	private static byte[] sha256(String value) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

}
