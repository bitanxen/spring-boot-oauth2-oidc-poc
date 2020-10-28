package in.bitanxen.poc.exception;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

public class AuthorizationPendingException  extends OAuth2Exception {

        /**
         * @param msg
         */
	public AuthorizationPendingException(String msg) {
	    super(msg);
	}

    @Override
    public String getOAuth2ErrorCode() {
        return "authorization_pending";
    }
}
