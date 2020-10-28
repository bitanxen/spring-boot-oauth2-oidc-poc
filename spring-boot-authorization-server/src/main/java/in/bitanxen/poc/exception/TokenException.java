package in.bitanxen.poc.exception;

public class TokenException extends RuntimeException {
    public TokenException(String msg) {
        super(msg);
    }

    public TokenException(Throwable t) {
        super(t);
    }
}
