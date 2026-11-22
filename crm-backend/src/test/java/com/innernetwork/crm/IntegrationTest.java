package com.innernetwork.crm;

import java.nio.file.Path;
import java.util.UUID;

import com.jayway.jsonpath.JsonPath;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Base class for tests against a real PostgreSQL, set up exactly like production: the same
 * init script creates the owner and the restricted app role, and the app connects as the app role.
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class IntegrationTest {

	static final String OWNER_PASSWORD = "owner-test-password";

	static final String APP_PASSWORD = "app-test-password";

	static final GenericContainer<?> POSTGRES = new GenericContainer<>("postgres:17-alpine")
		.withEnv("POSTGRES_PASSWORD", "admin-test-password")
		.withEnv("CRM_DB_OWNER_PASSWORD", OWNER_PASSWORD)
		.withEnv("CRM_DB_APP_PASSWORD", APP_PASSWORD)
		.withCopyFileToContainer(MountableFile.forHostPath(Path.of("docker/postgres/init/01-roles.sh"), 0755),
				"/docker-entrypoint-initdb.d/01-roles.sh")
		.withExposedPorts(5432)
		.waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));

	static {
		POSTGRES.start();
	}

	@DynamicPropertySource
	static void databaseProperties(DynamicPropertyRegistry registry) {
		String url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/crm";
		registry.add("spring.datasource.url", () -> url);
		registry.add("spring.datasource.username", () -> "crm_app");
		registry.add("spring.datasource.password", () -> APP_PASSWORD);
		registry.add("spring.flyway.url", () -> url);
		registry.add("spring.flyway.user", () -> "crm_owner");
		registry.add("spring.flyway.password", () -> OWNER_PASSWORD);
		registry.add("crm.jwt.secret", () -> "dGVzdC1vbmx5LWtleS10ZXN0LW9ubHkta2V5LTEyMzQ1Njc4OTA=");
		registry.add("crm.cors.allowed-origins", () -> "http://localhost:5173");
		// All tests share one IP (127.0.0.1); keep the per-IP limit out of the way of unrelated tests.
		registry.add("crm.login-rate-limit.max-failures-per-ip", () -> "1000");
	}

	@Autowired
	protected MockMvc mvc;

	/** A tenant created through the real signup endpoint. */
	protected record Account(String email, String password, String accessToken, String refreshCookie, UUID tenantId) {

		public String bearer() {
			return "Bearer " + this.accessToken;
		}

	}

	protected Account signup(String company) throws Exception {
		String email = "admin-" + UUID.randomUUID() + "@example.ro";
		String password = "correct horse battery staple";
		MvcResult result = this.mvc.perform(post("/api/auth/signup")
			.contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"companyName": "%s", "cui": "RO12345678", "fullName": "Ana Pop",
					 "email": "%s", "password": "%s"}
					""".formatted(company, email, password)))
			.andExpect(status().isCreated())
			.andReturn();
		String token = JsonPath.read(result.getResponse().getContentAsString(), "$.accessToken");
		String cookie = result.getResponse().getCookie("crm_refresh").getValue();
		String tenantId = this.mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
			.get("/api/me")
			.header("Authorization", "Bearer " + token))
			.andReturn()
			.getResponse()
			.getContentAsString();
		return new Account(email, password, token, cookie, UUID.fromString(JsonPath.read(tenantId, "$.tenantId")));
	}

	protected String createContact(Account account, String firstName) throws Exception {
		MvcResult result = this.mvc.perform(post("/api/contacts")
			.header("Authorization", account.bearer())
			.contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"firstName": "%s", "lastName": "Ionescu", "phone": "+40 721 000 000"}
					""".formatted(firstName)))
			.andExpect(status().isCreated())
			.andReturn();
		return JsonPath.read(result.getResponse().getContentAsString(), "$.id");
	}

}
