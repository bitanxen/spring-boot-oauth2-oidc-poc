package in.bitanxen.poc.model.statics;

import java.util.Arrays;

public enum SubjectType {
    PAIRWISE("pairwise"),
    PUBLIC("public");

    private final String value;

    SubjectType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static SubjectType getByValue(String value) {
        return Arrays.stream(SubjectType.values()).filter(authMethod -> authMethod.getValue().equals(value)).findAny().orElse(null);
    }
}
