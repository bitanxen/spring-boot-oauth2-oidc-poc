package in.bitanxen.poc.model.statics;

import lombok.Getter;

public enum SystemScopeType {
    OFFLINE_ACCESS("offline_access", "Scope manages access token and refresh token", "", false, false),
    OPENID_SCOPE("openid", "Scope manages Open ID Connect", "", false, false),
    REGISTRATION_TOKEN_SCOPE("registration-token", "Scope manages dynamic client registrations", "", false, false),
    RESOURCE_TOKEN_SCOPE("resource-token", "Scope manages client-style protected resources", "", false, false);

    @Getter
    private final String value;
    @Getter
    private final String description;
    @Getter
    private final String icon;
    @Getter
    private final boolean defaultScope;
    @Getter
    private final boolean restricted;

    SystemScopeType(String value, String description, String icon, boolean defaultScope, boolean restricted) {
        this.value = value;
        this.description = description;
        this.icon = icon;
        this.defaultScope = defaultScope;
        this.restricted = restricted;
    }

}
