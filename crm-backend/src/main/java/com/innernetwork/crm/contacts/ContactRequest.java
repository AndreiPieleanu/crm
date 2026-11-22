package com.innernetwork.crm.contacts;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for creating or updating a contact. It has no id, tenant or owner fields, so a client
 * cannot move a contact to another tenant by sending extra JSON properties.
 */
record ContactRequest(
		@NotBlank @Size(max = 100) String firstName,
		@Size(max = 100) String lastName,
		@Email @Size(max = 254) String email,
		@Pattern(regexp = "^[+0-9 ()./-]{3,30}$", message = "must be a valid phone number") String phone,
		@Size(max = 200) String companyName,
		@Size(max = 5000) String notes) {

	/** Trims values and turns empty strings into null. */
	ContactRequest normalized() {
		return new ContactRequest(clean(this.firstName), clean(this.lastName), clean(this.email), clean(this.phone),
				clean(this.companyName), clean(this.notes));
	}

	private static String clean(String value) {
		if (value == null) {
			return null;
		}
		String stripped = value.strip();
		return stripped.isEmpty() ? null : stripped;
	}

}
