package com.innernetwork.crm.tenancy;

import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * Refuses to start the app if tenant isolation could be silently switched off.
 *
 * <p>Row-Level Security does not apply to superusers, to roles with BYPASSRLS, or to the owner of
 * a table. A wrong database user in production would therefore leak every tenant's data without
 * any error. This check turns that mistake into a failed startup. It also fails when a table has
 * no RLS enabled, so a new migration cannot forget it. A table that is truly shared between
 * tenants must enable RLS with an explicit {@code USING (true)} policy.
 */
@Component
class TenantIsolationGuard implements InitializingBean {

	private final JdbcClient jdbc;

	TenantIsolationGuard(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	@Override
	public void afterPropertiesSet() {
		Boolean unsafeRole = this.jdbc
			.sql("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
			.query(Boolean.class)
			.single();
		if (unsafeRole) {
			throw new IllegalStateException(
					"The app's database user is a superuser or has BYPASSRLS. Use the restricted app role.");
		}

		Integer ownedTables = this.jdbc
			.sql("SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user")
			.query(Integer.class)
			.single();
		if (ownedTables > 0) {
			throw new IllegalStateException(
					"The app's database user owns tables, so Row-Level Security would not apply to it. "
							+ "Run migrations as the owner role and the app as the restricted role.");
		}

		List<String> tablesWithoutRls = this.jdbc.sql("""
				SELECT c.relname
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = 'public'
				  AND c.relkind = 'r'
				  AND c.relname <> 'flyway_schema_history'
				  AND NOT c.relrowsecurity
				""").query(String.class).list();
		if (!tablesWithoutRls.isEmpty()) {
			throw new IllegalStateException("Tables without Row-Level Security: " + tablesWithoutRls);
		}
	}

}
