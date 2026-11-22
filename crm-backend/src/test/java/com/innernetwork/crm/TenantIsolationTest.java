package com.innernetwork.crm;

import java.util.UUID;

import com.innernetwork.crm.auth.UserAccounts;
import com.innernetwork.crm.tenancy.TenantContext;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** One company must never see, change or delete another company's data. */
class TenantIsolationTest extends IntegrationTest {

	@Autowired
	JdbcClient jdbc;

	@Autowired
	UserAccounts users;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Test
	void companyCannotReadChangeOrDeleteAnotherCompanysContacts() throws Exception {
		Account alpha = signup("Alpha SRL");
		Account beta = signup("Beta SRL");
		String alphaContact = createContact(alpha, "Maria");

		this.mvc.perform(get("/api/contacts").header("Authorization", beta.bearer()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.items", hasSize(0)))
			.andExpect(jsonPath("$.total").value(0));
		this.mvc.perform(get("/api/contacts/" + alphaContact).header("Authorization", beta.bearer()))
			.andExpect(status().isNotFound());
		this.mvc.perform(put("/api/contacts/" + alphaContact)
			.header("Authorization", beta.bearer())
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"firstName\": \"Hacked\"}"))
			.andExpect(status().isNotFound());
		this.mvc.perform(delete("/api/contacts/" + alphaContact).header("Authorization", beta.bearer()))
			.andExpect(status().isNotFound());

		this.mvc.perform(get("/api/contacts/" + alphaContact).header("Authorization", alpha.bearer()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.firstName").value("Maria"));
	}

	@Test
	void tenantIdInTheRequestBodyIsIgnored() throws Exception {
		Account alpha = signup("Alpha SRL");
		Account beta = signup("Beta SRL");

		this.mvc.perform(post("/api/contacts")
			.header("Authorization", alpha.bearer())
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"firstName\": \"Ion\", \"tenantId\": \"%s\"}".formatted(beta.tenantId())))
			.andExpect(status().isCreated());

		this.mvc.perform(get("/api/contacts").header("Authorization", beta.bearer()))
			.andExpect(jsonPath("$.total").value(0));
		this.mvc.perform(get("/api/contacts").header("Authorization", alpha.bearer()))
			.andExpect(jsonPath("$.total").value(1));
	}

	@Test
	void databaseShowsNothingWhenNoTenantIsSet() throws Exception {
		Account alpha = signup("Alpha SRL");
		createContact(alpha, "Elena");

		long visibleWithoutTenant = this.jdbc.sql("SELECT count(*) FROM contacts").query(Long.class).single();
		long usersWithoutTenant = this.jdbc.sql("SELECT count(*) FROM users").query(Long.class).single();

		assertThat(visibleWithoutTenant).isZero();
		assertThat(usersWithoutTenant).isZero();
	}

	@Test
	void databaseRejectsWritingIntoAnotherTenant() throws Exception {
		Account alpha = signup("Alpha SRL");
		Account beta = signup("Beta SRL");

		assertThatThrownBy(() -> TenantContext.runAs(alpha.tenantId(), () -> this.jdbc
			.sql("INSERT INTO contacts (tenant_id, first_name) VALUES (:tenant, 'Intrus')")
			.param("tenant", beta.tenantId())
			.update()))
			.rootCause()
			.hasMessageContaining("violates row-level security policy");
	}

	@Test
	void onlyAdminsCanDeleteContacts() throws Exception {
		Account alpha = signup("Alpha SRL");
		String contactId = createContact(alpha, "Andrei");
		String userEmail = "user-" + UUID.randomUUID() + "@example.ro";
		TenantContext.runAs(alpha.tenantId(), () -> this.users.createUser(userEmail, "Vlad Popescu",
				this.passwordEncoder.encode(alpha.password()), "USER"));

		String userToken = com.jayway.jsonpath.JsonPath.read(this.mvc.perform(post("/api/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(userEmail, alpha.password())))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString(), "$.accessToken");

		this.mvc.perform(delete("/api/contacts/" + contactId).header("Authorization", "Bearer " + userToken))
			.andExpect(status().isForbidden());
		this.mvc.perform(delete("/api/contacts/" + contactId).header("Authorization", alpha.bearer()))
			.andExpect(status().isNoContent());
	}

}
