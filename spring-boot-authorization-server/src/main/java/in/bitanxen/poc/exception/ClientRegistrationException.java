package in.bitanxen.poc.exception;

public class ClientRegistrationException extends RuntimeException {

    public ClientRegistrationException(String msg) {
        super(msg);
    }

    public ClientRegistrationException(Throwable throwable) {
        super(throwable);
    }

}
