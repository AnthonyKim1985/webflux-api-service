package com.example.webfluxapiservice.exception;

/**
 * @author Anthony Jinhyuk Kim
 * @version 1.0.0
 * @since 2018-10-08
 */
public class InvalidAuthRequestException extends ObjectNotFoundException {
    public InvalidAuthRequestException() {
        super("Invalid SignInRequest is found.");
    }
}
