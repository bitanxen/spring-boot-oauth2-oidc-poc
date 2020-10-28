package in.bitanxen.poc.exception;

public class AuthenticationHolderException extends RuntimeException {

    public AuthenticationHolderException(String msg) {
        super(msg);
    }

    public AuthenticationHolderException(Throwable t) {
        super(t);
    }
}
