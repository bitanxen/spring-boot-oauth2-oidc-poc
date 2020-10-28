package in.bitanxen.poc.exception;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

public class DeviceCodeException extends OAuth2Exception {

    public DeviceCodeException(String msg) {
        super(msg);
    }

    @Override
    public String getOAuth2ErrorCode() {
        return super.getOAuth2ErrorCode();
    }

}
