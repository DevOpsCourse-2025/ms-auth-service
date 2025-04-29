package com.chiops.auth.controllers;

import com.chiops.auth.libs.dtos.request.AdministratorRequestDTO;
import com.chiops.auth.libs.exceptions.entities.ErrorResponse;
import com.chiops.auth.libs.exceptions.exception.BadRequestException;
import com.chiops.auth.libs.exceptions.exception.InternalServerException;
import com.chiops.auth.libs.exceptions.exception.MethodNotAllowedException;
import com.chiops.auth.libs.exceptions.exception.NotFoundException;
import com.chiops.auth.providers.AuthProvider;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Error;
import reactor.core.publisher.Mono;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

@ExecuteOn(TaskExecutors.BLOCKING)
@Secured(SecurityRule.IS_ANONYMOUS)
@Controller("/auth")
public class AuthController {

    private final AuthProvider authProvider;

    public AuthController(AuthProvider authProvider) {
        this.authProvider = authProvider;
    }

    @Post("/login")
    public Mono<HttpResponse<?>> login(@Body AdministratorRequestDTO dto) {
        try {
            return authProvider.login(dto);
        } catch (BadRequestException e) {
            return Mono.error(new BadRequestException("Error de solicitud al iniciar sesión: " + e.getMessage()));
        } catch (InternalServerException e) {
            return Mono.error(new InternalServerException("Error interno al iniciar sesión: " + e.getMessage()));
        }
    }

    @Post("/register")
    public Mono<HttpResponse<?>> register(@Body AdministratorRequestDTO dto) {
        try {
            return authProvider.register(dto);
        } catch (BadRequestException e) {
            return Mono.error(new BadRequestException("Error de solicitud al registrar administrador: " + e.getMessage()));
        } catch (InternalServerException e) {
            return Mono.error(new InternalServerException("Error interno al registrar administrador: " + e.getMessage()));
        }
    }

    @Error(status = HttpStatus.NOT_FOUND, global = true)
    public HttpResponse<ErrorResponse> handleNotFound(HttpRequest<?> request) {
        throw new NotFoundException("Endpoint " + request.getPath() + " no encontrado");
    }

    @Error(status = HttpStatus.METHOD_NOT_ALLOWED, global = true)
    public HttpResponse<ErrorResponse> handleMethodNotAllowed(HttpRequest<?> request) {
        throw new MethodNotAllowedException("Método " + request.getMethod() + " no permitido para " + request.getPath());
    }
}
