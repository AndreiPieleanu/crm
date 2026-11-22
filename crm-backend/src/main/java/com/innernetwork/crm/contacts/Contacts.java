package com.innernetwork.crm.contacts;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Database access for contacts.
 *
 * <p>There is no "WHERE tenant_id = ..." here on purpose: Row-Level Security filters every query
 * to the current tenant, and fills in tenant_id on insert. A query cannot forget it.
 */
@Repository
class Contacts {

	record Contact(UUID id, String firstName, String lastName, String email, String phone, String companyName,
			String notes, OffsetDateTime createdAt, OffsetDateTime updatedAt) {
	}

	private static final String COLUMNS = """
			id, first_name, last_name, email, phone, company_name, notes, created_at, updated_at""";

	private final JdbcClient jdbc;

	Contacts(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	List<Contact> list(int limit, int offset) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM contacts ORDER BY created_at DESC, id LIMIT :limit OFFSET :offset")
			.param("limit", limit)
			.param("offset", offset)
			.query(Contact.class)
			.list();
	}

	long count() {
		return this.jdbc.sql("SELECT count(*) FROM contacts").query(Long.class).single();
	}

	Optional<Contact> find(UUID id) {
		return this.jdbc.sql("SELECT " + COLUMNS + " FROM contacts WHERE id = :id")
			.param("id", id)
			.query(Contact.class)
			.optional();
	}

	Contact insert(ContactRequest request, UUID createdBy) {
		return this.jdbc.sql("""
				INSERT INTO contacts (first_name, last_name, email, phone, company_name, notes, created_by)
				VALUES (:firstName, :lastName, :email, :phone, :companyName, :notes, :createdBy)
				RETURNING\s""" + COLUMNS)
			.params(fields(request))
			.param("createdBy", createdBy)
			.query(Contact.class)
			.single();
	}

	Optional<Contact> update(UUID id, ContactRequest request) {
		return this.jdbc.sql("""
				UPDATE contacts
				SET first_name = :firstName, last_name = :lastName, email = :email, phone = :phone,
				    company_name = :companyName, notes = :notes, updated_at = now()
				WHERE id = :id
				RETURNING\s""" + COLUMNS)
			.params(fields(request))
			.param("id", id)
			.query(Contact.class)
			.optional();
	}

	private static Map<String, Object> fields(ContactRequest request) {
		ContactRequest r = request.normalized();
		Map<String, Object> fields = new HashMap<>();
		fields.put("firstName", r.firstName());
		fields.put("lastName", r.lastName());
		fields.put("email", r.email());
		fields.put("phone", r.phone());
		fields.put("companyName", r.companyName());
		fields.put("notes", r.notes());
		return fields;
	}

	boolean delete(UUID id) {
		return this.jdbc.sql("DELETE FROM contacts WHERE id = :id").param("id", id).update() == 1;
	}

}
