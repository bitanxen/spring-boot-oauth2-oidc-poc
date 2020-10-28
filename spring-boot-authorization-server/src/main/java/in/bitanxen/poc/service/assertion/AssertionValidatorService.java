package in.bitanxen.poc.service.assertion;

import com.nimbusds.jwt.JWT;

public interface AssertionValidatorService {
    boolean isValid(JWT assertion);
}
