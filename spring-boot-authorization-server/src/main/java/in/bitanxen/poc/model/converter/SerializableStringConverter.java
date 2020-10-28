package in.bitanxen.poc.model.converter;

import lombok.extern.log4j.Log4j2;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.Serializable;
import java.util.Date;

@Converter
@Log4j2
public class SerializableStringConverter implements AttributeConverter<Serializable, String> {

    @Override
    public String convertToDatabaseColumn(Serializable attribute) {
        if (attribute == null) {
            return null;
        } else if (attribute instanceof String) {
            return (String) attribute;
        } else if (attribute instanceof Long) {
            return attribute.toString();
        } else if (attribute instanceof Date) {
            return Long.toString(((Date)attribute).getTime());
        } else {
            log.warn("Dropping data from request: " + attribute + " :: " + attribute.getClass());
            return null;
        }
    }

    @Override
    public Serializable convertToEntityAttribute(String dbData) {
        return dbData;
    }

}
