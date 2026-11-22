package com.innernetwork.crm.tenancy;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Knows which tenant (client company) the current code runs for.
 *
 * <p>The tenant comes only from the signed access token ({@code tid} claim), never from request
 * parameters or headers. Code that runs before a user is logged in (signup, login, token refresh)
 * sets the tenant explicitly with {@link #callAs}.
 */
public final class TenantContext {

	public static final String TENANT_CLAIM = "tid";

	private static final ThreadLocal<UUID> EXPLICIT_TENANT = new ThreadLocal<>();

	private TenantContext() {
	}

	public static Optional<UUID> currentTenantId() {
		UUID explicit = EXPLICIT_TENANT.get();
		if (explicit != null) {
			return Optional.of(explicit);
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof JwtAuthenticationToken jwtAuth) {
			String tenantId = jwtAuth.getToken().getClaimAsString(TENANT_CLAIM);
			if (tenantId != null) {
				return Optional.of(UUID.fromString(tenantId));
			}
		}
		return Optional.empty();
	}

	/** Runs {@code action} with {@code tenantId} as the current tenant, then restores the previous one. */
	public static <T> T callAs(UUID tenantId, Supplier<T> action) {
		Objects.requireNonNull(tenantId, "tenantId");
		UUID previous = EXPLICIT_TENANT.get();
		EXPLICIT_TENANT.set(tenantId);
		try {
			return action.get();
		}
		finally {
			if (previous == null) {
				EXPLICIT_TENANT.remove();
			}
			else {
				EXPLICIT_TENANT.set(previous);
			}
		}
	}

	public static void runAs(UUID tenantId, Runnable action) {
		callAs(tenantId, () -> {
			action.run();
			return null;
		});
	}

}
