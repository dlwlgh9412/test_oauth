package com.copago.test_oauth.app.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class NotSupportPlatform extends RuntimeException {
    public NotSupportPlatform(String message) {
        super(message);
    }
}
