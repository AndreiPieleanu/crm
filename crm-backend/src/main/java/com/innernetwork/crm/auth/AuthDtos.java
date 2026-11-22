package com.innernetwork.crm.auth;

import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Request and response bodies of the auth endpoints. Requests contain no tenant or role fields. */
public interface AuthDtos {

	record SignupRequest(
			@NotBlank @Size(max = 200) String companyName,
			@Pattern(regexp = "^\\s*(RO|ro)?\\s*[0-9]{2,10}\\s*$", message = "must be a valid CUI") String cui,
			@NotBlank @Size(max = 200) String fullName,
			@NotBlank @Email @Size(max = 254) String email,
			@NotBlank @Size(min = 12, max = 128) String password) {
	}

	record LoginRequest(
			@NotBlank @Size(max = 254) String email,
			@NotBlank @Size(max = 128) String password) {
	}

	record TokenResponse(String accessToken, String tokenType, long expiresIn) {
	}

	record MeResponse(UUID userId, UUID tenantId, String email, String fullName, String role, String companyName) {
	}

}
