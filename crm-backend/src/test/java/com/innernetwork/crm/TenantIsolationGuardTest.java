package com.innernetwork.crm;

import org.junit.jupiter.api.Test;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The app must refuse to start with a database user for which Row-Level Security does not apply. */
class TenantIsolationGuardTest {

	@Test
	void appDoesNotStartWhenItConnectsAsTheTableOwner() {
		IntegrationTest.POSTGRES.start();
		String url = "jdbc:postgresql://" + IntegrationTest.POSTGRES.getHost() + ":"
				+ IntegrationTest.POSTGRES.getMappedPort(5432) + "/crm";

		SpringApplicationBuilder app = new SpringApplicationBuilder(CrmBackendApplication.class)
			.web(WebApplicationType.NONE);

		assertThatThrownBy(() -> app.run(
				"--spring.datasource.url=" + url,
				"--spring.datasource.username=crm_owner",
				"--spring.datasource.password=" + IntegrationTest.OWNER_PASSWORD,
				"--spring.flyway.url=" + url,
				"--spring.flyway.user=crm_owner",
				"--spring.flyway.password=" + IntegrationTest.OWNER_PASSWORD,
				"--crm.jwt.secret=dGVzdC1vbmx5LWtleS10ZXN0LW9ubHkta2V5LTEyMzQ1Njc4OTA="))
			.rootCause()
			.hasMessageContaining("owns tables");
	}

}
