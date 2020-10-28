package in.bitanxen.poc.exception;

public class ScopeException extends RuntimeException {

    public ScopeException(String msg) {
        super(msg);
    }

    public ScopeException(Throwable t) {
        super(t);
    }
}
