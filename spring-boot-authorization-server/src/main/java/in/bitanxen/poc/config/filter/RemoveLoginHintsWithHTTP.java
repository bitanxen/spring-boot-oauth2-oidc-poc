package in.bitanxen.poc.config.filter;

import com.google.common.base.Strings;

public class RemoveLoginHintsWithHTTP implements LoginHintExtractor {

    @Override
    public String extractHint(String loginHint) {
        if (Strings.isNullOrEmpty(loginHint)) {
            return null;
        } else {
            if (loginHint.startsWith("http")) {
                return null;
            } else {
                return loginHint;
            }
        }
    }
}
