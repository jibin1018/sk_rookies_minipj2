package com.company.portal.exception;

public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s를 찾을 수 없습니다. %s: %s", resourceName, fieldName, fieldValue));
    }
}
