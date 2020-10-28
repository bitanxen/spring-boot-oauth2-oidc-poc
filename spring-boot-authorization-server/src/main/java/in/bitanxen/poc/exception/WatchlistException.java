package in.bitanxen.poc.exception;

public class WatchlistException extends RuntimeException {

    public WatchlistException(String msg) {
        super(msg);
    }

    public WatchlistException(Throwable t) {
        super(t);
    }
}
