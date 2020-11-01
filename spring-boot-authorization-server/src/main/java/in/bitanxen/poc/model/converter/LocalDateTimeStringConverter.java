package in.bitanxen.poc.model.converter;

import javax.persistence.AttributeConverter;
import java.time.LocalDateTime;

public class LocalDateTimeStringConverter implements AttributeConverter<LocalDateTime, String> {

    @Override
    public String convertToDatabaseColumn(LocalDateTime attribute) {
        return null;
    }

    @Override
    public LocalDateTime convertToEntityAttribute(String dbData) {
        return null;
    }
}
