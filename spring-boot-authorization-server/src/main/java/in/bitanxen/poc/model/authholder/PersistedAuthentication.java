package in.bitanxen.poc.model.authholder;

import in.bitanxen.poc.model.converter.BooleanToStringConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@Entity(name = "TB_SAVED_USER_AUTH")
public class PersistedAuthentication implements Authentication {

    @Id
    @GenericGenerator(name = "Application-Generic-Generator",
            strategy = "in.bitanxen.poc.config.ApplicationGenericGenerator"
    )
    @GeneratedValue(generator = "Application-Generic-Generator")
    @Column(name = "AUTH_ID", nullable = false, unique = true)
    private String id;

    @Column(name = "AUTH_NAME", nullable = false)
    private String name;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "persistedAuthentication")
    private Set<PersistedAuthenticationAuthority> authorities = new HashSet<>();

    @Column(name = "IS_AUTHENTICATED")
    @Convert(converter = BooleanToStringConverter.class)
    private boolean authenticated;

    @Column(name = "SOURCE_CLASS")
    private String sourceClass;

    public PersistedAuthentication(Authentication src) {
        Set<PersistedAuthenticationAuthority> persistedAuthenticationAuthorities = src.getAuthorities() == null ? null : src.getAuthorities()
                .stream()
                .map(grantedAuthority -> new PersistedAuthenticationAuthority(this, grantedAuthority.getAuthority()))
                .collect(Collectors.toSet());

        setName(src.getName());
        setAuthorities(persistedAuthenticationAuthorities);
        setAuthenticated(src.isAuthenticated());

        if (src instanceof PersistedAuthentication) {
            // if we're copying in a saved auth, carry over the original class name
            setSourceClass(((PersistedAuthentication) src).getSourceClass());
        } else {
            setSourceClass(src.getClass().getName());
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream().map(PersistedAuthenticationAuthority::getAuthority).collect(Collectors.toSet());
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getDetails() {
        return getName();
    }

    @Override
    public Object getPrincipal() {
        return getName();
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return name;
    }
}
