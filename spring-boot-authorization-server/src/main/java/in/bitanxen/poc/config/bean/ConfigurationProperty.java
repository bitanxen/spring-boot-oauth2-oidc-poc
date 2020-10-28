package in.bitanxen.poc.config.bean;

import com.google.common.collect.Lists;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Locale;

@Getter
@Setter
@Log4j2
public class ConfigurationProperty {
    private String issuer;
    private boolean forceHttps;
    private boolean dualClient;
    private boolean heartMode;
    private boolean allowCompleteDeviceCodeUri;
    private Locale locale = Locale.ENGLISH;
    private List<String> languageNamespaces = Lists.newArrayList("messages");
    private String jwkUri;

    @PostConstruct
    public void checkConfigConsistency() {
        if (!StringUtils.startsWithIgnoreCase(issuer, "https")) {
            if (this.forceHttps) {
                log.error("Configured issuer url is not using https scheme. Server will be shut down!");
                throw new BeanCreationException("Issuer is not using https scheme as required: " + issuer);
            }
            else {
                log.warn("WARNING: Configured issuer url is not using https scheme");
            }
        }

        if (languageNamespaces == null || languageNamespaces.isEmpty()) {
            log.error("No configured language namespaces! Text rendering will fail!");
        }
    }
}
