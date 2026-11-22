package com.innernetwork.crm.auth;

import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Database access for tenants and users. Every query below runs under Row-Level Security. */
@Repository
public class UserAccounts {

	public record LoginRow(UUID id, UUID tenantId, String passwordHash, String role, boolean enabled) {
	}

	public record UserRow(UUID id, UUID tenantId, String email, String fullName, String role, boolean enabled,
			String companyName) {
	}

	private final JdbcClient jdbc;

	UserAccounts(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	/** Looks up a user before the tenant is known, through a narrow SECURITY DEFINER function. */
	Optional<LoginRow> findForLogin(String normalizedEmail) {
		return this.jdbc.sql("SELECT * FROM auth_find_user_by_email(:email)")
			.param("email", normalizedEmail)
			.query(LoginRow.class)
			.optional();
	}

	void createTenant(UUID tenantId, String name, String cui) {
		this.jdbc.sql("INSERT INTO tenants (id, name, cui) VALUES (:id, :name, :cui)")
			.param("id", tenantId)
			.param("name", name)
			.param("cui", cui)
			.update();
	}

	/** Creates a user in the current tenant (tenant_id is filled in by the database). */
	public UUID createUser(String normalizedEmail, String fullName, String passwordHash, String role) {
		return this.jdbc.sql("""
				INSERT INTO users (email, full_name, password_hash, role)
				VALUES (:email, :fullName, :passwordHash, :role)
				RETURNING id
				""")
			.param("email", normalizedEmail)
			.param("fullName", fullName)
			.param("passwordHash", passwordHash)
			.param("role", role)
			.query(UUID.class)
			.single();
	}

	Optional<UserRow> findById(UUID userId) {
		return this.jdbc.sql("""
				SELECT u.id, u.tenant_id, u.email, u.full_name, u.role, u.enabled, t.name AS company_name
				FROM users u
				JOIN tenants t ON t.id = u.tenant_id
				WHERE u.id = :id
				""")
			.param("id", userId)
			.query(UserRow.class)
			.optional();
	}

	void updatePasswordHash(UUID userId, String passwordHash) {
		this.jdbc.sql("UPDATE users SET password_hash = :hash WHERE id = :id")
			.param("hash", passwordHash)
			.param("id", userId)
			.update();
	}

}
