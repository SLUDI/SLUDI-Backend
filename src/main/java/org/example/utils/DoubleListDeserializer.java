package org.example.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class DoubleListDeserializer extends JsonDeserializer<List<Double>> {
    @Override
    public List<Double> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonToken token = p.getCurrentToken();

        // Case 1: Already an array
        if (token == JsonToken.START_ARRAY) {
            return p.readValueAs(new TypeReference<List<Double>>() {
            });
        }

        // Case 2: String that looks like an array
        if (token == JsonToken.VALUE_STRING) {
            String raw = p.getValueAsString();
            raw = raw.replace("[", "").replace("]", "");

            return Arrays.stream(raw.split(","))
                    .map(String::trim)
                    .map(Double::parseDouble)
                    .collect(Collectors.toList());
        }

        throw new IOException("Invalid faceEmbedding format");
    }
}
