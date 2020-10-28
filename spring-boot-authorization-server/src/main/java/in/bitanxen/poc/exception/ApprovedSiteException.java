package in.bitanxen.poc.exception;

public class ApprovedSiteException extends RuntimeException {
    public ApprovedSiteException(String msg) {
        super(msg);
    }

    public ApprovedSiteException(Throwable t) {
        super(t);
    }
}
