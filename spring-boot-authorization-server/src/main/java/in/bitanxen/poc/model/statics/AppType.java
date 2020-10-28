package in.bitanxen.poc.model.statics;

import java.util.Arrays;

public enum AppType {
    WEB("web"),
    NATIVE("native");

    private final String value;

    AppType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static AppType getByValue(String value) {
        return Arrays.stream(AppType.values()).filter(authMethod -> authMethod.getValue().equals(value)).findAny().orElse(null);
    }
}
