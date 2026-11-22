package com.innernetwork.crm.contacts;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import com.innernetwork.crm.contacts.Contacts.Contact;
import com.innernetwork.crm.web.NotFoundException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Contacts of the logged-in user's company. A contact of another company answers 404, exactly
 * like a contact that does not exist, so ids of other tenants cannot be probed.
 */
@RestController
@RequestMapping("/api/contacts")
class ContactController {

	record ContactPage(List<Contact> items, int page, int size, long total) {
	}

	private final Contacts contacts;

	ContactController(Contacts contacts) {
		this.contacts = contacts;
	}

	@GetMapping
	ContactPage list(@RequestParam(defaultValue = "0") @Min(0) @Max(100_000) int page,
			@RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
		return new ContactPage(this.contacts.list(size, page * size), page, size, this.contacts.count());
	}

	@GetMapping("/{id}")
	Contact get(@PathVariable UUID id) {
		return this.contacts.find(id).orElseThrow(NotFoundException::new);
	}

	@PostMapping
	ResponseEntity<Contact> create(@Valid @RequestBody ContactRequest request, @AuthenticationPrincipal Jwt jwt) {
		Contact created = this.contacts.insert(request, UUID.fromString(jwt.getSubject()));
		return ResponseEntity.created(URI.create("/api/contacts/" + created.id())).body(created);
	}

	@PutMapping("/{id}")
	Contact update(@PathVariable UUID id, @Valid @RequestBody ContactRequest request) {
		return this.contacts.update(id, request).orElseThrow(NotFoundException::new);
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	ResponseEntity<Void> delete(@PathVariable UUID id) {
		if (!this.contacts.delete(id)) {
			throw new NotFoundException();
		}
		return ResponseEntity.noContent().build();
	}

}
