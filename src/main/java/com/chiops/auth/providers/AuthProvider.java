package com.chiops.auth.providers;

import com.chiops.auth.libs.dtos.response.AdministratorResponseDTO;
import com.chiops.auth.libs.exceptions.exception.BadRequestException;
import com.chiops.auth.libs.exceptions.exception.ConflictException;
import com.chiops.auth.libs.exceptions.exception.InternalServerException;
import com.chiops.auth.libs.exceptions.exception.NotAuthenticatedException;
import com.chiops.auth.libs.exceptions.exception.NotFoundException;
import com.chiops.auth.libs.clients.AdministratorClient;
import com.chiops.auth.libs.dtos.request.AdministratorRequestDTO;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.token.generator.TokenGenerator;
import jakarta.inject.Singleton;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import reactor.core.publisher.Mono;

@Singleton
public class AuthProvider {

  private final AdministratorClient administratorClient;
  private final TokenGenerator tokenGenerator;

  public AuthProvider(AdministratorClient administratorClient, TokenGenerator tokenGenerator) {
    this.administratorClient = administratorClient;
    this.tokenGenerator = tokenGenerator;
  }

  public Mono<HttpResponse<?>> login(AdministratorRequestDTO dto) {
    return Mono.fromCallable(() -> {
        try {
            AdministratorResponseDTO response = administratorClient.signInAdministrator(dto);

            if (response == null) {
                throw new NotAuthenticatedException("Invalid credentials");
            }

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", response.getEmail());
            claims.put("name", response.getInvitationCode());

            Optional<String> token = tokenGenerator.generateToken(claims);

            return token
                    .<HttpResponse<?>>map(t -> HttpResponse.ok(Map.of("access_token", t)))
                    .orElseThrow(() -> new InternalServerException("Token generation failed"));
        } catch (HttpClientResponseException e) {
            HttpStatus status = e.getStatus();
            if (status != null) {
                switch (status.getCode()) {
                    case 400:
                        throw new BadRequestException("Invalid login input: make sure all fields are filled correctly.");
                    default:
                        throw new InternalServerException("Unexpected error during login: " + status);
                }
            } else {
                throw new InternalServerException("Login failed: " + e.getMessage());
            }
        }
    });
}

    public Mono<HttpResponse<?>> register(AdministratorRequestDTO dto) {
        return Mono.fromCallable(() -> {
            try {
                AdministratorResponseDTO response = administratorClient.createAdministrator(dto);

                return HttpResponse.ok(Map.of("message", "Registration successful"));
            } catch (HttpClientResponseException e) { 
                HttpStatus status = e.getStatus();
                if (status != null) {
                    switch (status.getCode()) {
                        case 400:
                        throw new BadRequestException("Invalid input: make sure all fields are filled correctly.");
                        case 409:
                            throw new ConflictException("An administrator with this email or invitation code already exists.");
                        default:
                            throw new InternalServerException("Unexpected error from administrator service: " + status);
                    }
                } else {
                    throw new InternalServerException("Registration failed: " + e.getMessage());
                }
            }
        });
    }

}
