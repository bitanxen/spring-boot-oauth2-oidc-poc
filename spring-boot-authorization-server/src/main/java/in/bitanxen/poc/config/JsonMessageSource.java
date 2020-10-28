package in.bitanxen.poc.config;

import com.google.common.base.Splitter;
import com.google.gson.*;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.support.AbstractMessageSource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.*;

@Log4j2
public class JsonMessageSource extends AbstractMessageSource {

    private final Map<Locale, List<JsonObject>> languageMaps = new HashMap<>();
    private final Locale fallbackLocale = Locale.ENGLISH;
    @Getter
    @Setter
    private Resource baseDirectory;

    @Getter
    @Setter
    private List<String> languageNamespaces;


    @Override
    protected MessageFormat resolveCode(String code, Locale locale) {
        List<JsonObject> languageMap = getLanguageMap(locale);
        String value = getValue(code, languageMap);

        if (value == null) {
            // if we haven't found anything, try the default locale
            languageMap = getLanguageMap(fallbackLocale);
            value = getValue(code, languageMap);
        }

        if (value == null) {
            return null;
        } else {
            return new MessageFormat(value, locale);
        }
    }

    private List<JsonObject> getLanguageMap(Locale locale) {

        if (!languageMaps.containsKey(locale)) {
            try {
                List<JsonObject> set = new ArrayList<>();
                for (String namespace : getLanguageNamespaces()) {
                    String filename = locale.getLanguage() + "_" + locale.getCountry() + File.separator + namespace + ".json";
                    Resource resource = getBaseDirectory().createRelative(filename);

                    if (!resource.exists()) {
                        // fallback to language only
                        log.debug("Fallback locale to language only.");
                        filename = locale.getLanguage() + File.separator + namespace + ".json";
                        resource = getBaseDirectory().createRelative(filename.trim());
                    }

                    if(resource.exists()) {
                        log.info("Load locale from {}", resource.getURI().getRawPath());
                        JsonElement jsonElement = JsonParser.parseReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8));
                        set.add(jsonElement.getAsJsonObject());
                    }
                }
                languageMaps.put(locale, set);
            } catch (FileNotFoundException e) {
                log.info("Unable to load locale because no messages file was found for locale {}", locale.getDisplayName());
                languageMaps.put(locale, null);
            } catch (JsonIOException | JsonSyntaxException | IOException e) {
                log.error("Unable to load locale", e);
            }
        }

        return languageMaps.get(locale);
    }

    private String getValue(String code, List<JsonObject> languages) {
        if (languages == null || languages.isEmpty()) {
            return null;
        }

        for (JsonObject lang : languages) {
            String value = getValue(code, lang);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private String getValue(String code, JsonObject lang) {
        if (lang == null) {
            return null;
        }

        JsonElement jsonElement = lang;
        Iterable<String> parts = Splitter.on('.').split(code);
        Iterator<String> it = parts.iterator();

        String value = null;

        while (it.hasNext()) {
            String p = it.next();
            if (jsonElement.isJsonObject()) {
                JsonObject o = jsonElement.getAsJsonObject();
                if (o.has(p)) {
                    jsonElement = o.get(p);
                    if (!it.hasNext()) {
                        // we've reached a leaf, grab it
                        if (jsonElement.isJsonPrimitive()) {
                            value = jsonElement.getAsString();
                        }
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        return value;
    }
}
