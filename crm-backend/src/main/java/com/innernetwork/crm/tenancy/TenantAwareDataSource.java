package com.innernetwork.crm.tenancy;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.jdbc.datasource.DelegatingDataSource;

/**
 * Sets {@code app.tenant_id} on every connection taken from the pool, so PostgreSQL Row-Level
 * Security knows which tenant's rows to show.
 *
 * <p>The value is written on <em>every</em> checkout, including an empty value when there is no
 * tenant. A pooled connection therefore never keeps the tenant of a previous request, and code
 * without a tenant sees no tenant rows at all.
 */
public class TenantAwareDataSource extends DelegatingDataSource {

	private static final String SET_TENANT_SQL = "SELECT set_config('app.tenant_id', ?, false)";

	public TenantAwareDataSource(DataSource target) {
		super(target);
	}

	@Override
	public Connection getConnection() throws SQLException {
		return applyTenant(super.getConnection());
	}

	@Override
	public Connection getConnection(String username, String password) throws SQLException {
		return applyTenant(super.getConnection(username, password));
	}

	private static Connection applyTenant(Connection connection) throws SQLException {
		String tenantId = TenantContext.currentTenantId().map(UUID::toString).orElse("");
		try (PreparedStatement statement = connection.prepareStatement(SET_TENANT_SQL)) {
			statement.setString(1, tenantId);
			statement.execute();
		}
		catch (SQLException ex) {
			connection.close();
			throw ex;
		}
		return connection;
	}

}
