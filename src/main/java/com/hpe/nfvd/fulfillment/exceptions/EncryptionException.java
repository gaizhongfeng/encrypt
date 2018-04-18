package com.hpe.nfvd.fulfillment.exceptions;

public class EncryptionException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -888203678173587805L;

	public EncryptionException() {
		super();
	}

	public EncryptionException(String message) {
		super(message);
	}

	public EncryptionException(String message, Throwable cause) {
		super(message, cause);
	}

	public EncryptionException(Throwable cause) {
		super(cause);
	}

}