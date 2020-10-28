package in.bitanxen.poc.model.converter;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.extern.log4j.Log4j2;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.text.ParseException;

@Converter
@Log4j2
public class JWTStringConverter implements AttributeConverter<JWT, String> {

    @Override
    public String convertToDatabaseColumn(JWT attribute) {
        if (attribute == null) {
            return null;
        }
        return attribute.serialize();
    }

    @Override
    public JWT convertToEntityAttribute(String dbData) {
        if(dbData == null) {
            return null;
        }
        try {
            return JWTParser.parse(dbData);
        } catch (ParseException e) {
            log.error("Unable to parse JWT", e);
            return null;
        }
    }
}
