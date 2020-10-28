package in.bitanxen.poc.exception;

public class ClientNotFoundException extends RuntimeException {

    public ClientNotFoundException(String msg) {
        super(msg);
    }

    public ClientNotFoundException(Throwable throwable) {
        super(throwable);
    }

}
