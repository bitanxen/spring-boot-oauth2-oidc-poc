package in.bitanxen.poc.model.statics;

import java.util.Arrays;

public enum AuthMethod {
    SECRET_POST("client_secret_post"),
    SECRET_BASIC("client_secret_basic"),
    SECRET_JWT("client_secret_jwt"),
    PRIVATE_KEY("private_key_jwt"),
    NONE("none");

    private final String value;

    AuthMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static AuthMethod getByValue(String value) {
        return Arrays.stream(AuthMethod.values()).filter(authMethod -> authMethod.getValue().equals(value)).findAny().orElse(null);
    }
}
